"""The three routes the Controller exposes, and deliberately nothing else.

    POST /spa_verify       a verified knock -> APPROVED or DENIED
    POST /session_review   the Gateway's live sessions -> the ones to revoke
    GET  /healthz          -> {"status": "ok"}

Everything else is 404; a verb a route does not serve is 405. All three sit
behind mutual TLS, /healthz included: there is no unauthenticated surface on
this component at all. That is the opposite of the resource node's choice,
and for the opposite reason - the node's /healthz must answer Docker before
any credential exists, whereas the only thing that ever probes the Controller
is a Gateway, which already holds a certificate.

Four decisions are worth stating outright.

**A malformed body is a denial, not an error to shrug at.** /spa_verify
answers a 400 with ``{"type": "DENIED", "reason": ...}``. The Gateway treats
anything that is not APPROVED as a refusal, so the shape of the reply and the
status code agree: a request the Controller could not read has not been
approved. Nothing in the parsing path can fall through to a grant, because a
grant is only ever built from a Decision the engine returned.

**The reason text is specific, and that is safe here.** The resource node
returns a fixed ``{"error": "unauthorized"}`` because its caller may be an
attacker probing which half of a stolen credential still works. The only
thing that can reach this handler is a Gateway holding a CA-signed
certificate, so a precise reason is diagnostic information for an operator,
not an oracle. What is never returned is a traceback: an unexpected exception
goes to the log in full and to the wire as a sentence.

**The peer certificate's subject is logged on every request.** A deployment
has several Gateways and one Controller; "a knock was denied" is not a useful
line unless it says which Gateway asked. The subject comes from the verified
peer certificate, so it is not something a caller can claim - and
``gateway_id_from_peer`` additionally refuses a peer that presents a SERVER
certificate, so an IDP or Controller certificate cannot be used to ask for a
decision.

**The grant's session id is minted here.** Decision deliberately has no
session id: it is a policy verdict, not a lease. The identifier that the
Gateway's firewall table and this Controller's later reviews both key on is
created at the moment an approval becomes a grant, which is here.
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import time
import traceback
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from shared.ca import cert_utils
from shared.utils.logger import get_logger, status

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from decision import Decision, PolicyEngine

log = get_logger("Ctl-HTTP")

PATH_SPA_VERIFY = "/spa_verify"
PATH_SESSION_REVIEW = "/session_review"
PATH_HEALTH = "/healthz"

TYPE_SPA_VERIFY = "SPA_VERIFY"
TYPE_SESSION_REVIEW = "SESSION_REVIEW"
TYPE_APPROVED = "APPROVED"
TYPE_DENIED = "DENIED"
TYPE_REVIEW_RESULT = "REVIEW_RESULT"
TYPE_ERROR = "ERROR"

# The same ACL vocabulary SDP_GATEWAY/firewall/segmentation.py enforces. Used
# here only to refuse a self-contradictory verdict, never to choose one.
ACL_FULL = "FULL"
ACL_LIMITED = "LIMITED"
ACL_DENY = "DENY"

# Fixed response bodies. Module constants rather than literals at the call
# site so it stays obvious that no request-derived text reaches them.
BODY_HEALTHY = {"status": "ok"}
BODY_NOT_FOUND = {"type": TYPE_ERROR, "reason": "not found"}
BODY_METHOD_NOT_ALLOWED = {"type": TYPE_ERROR, "reason": "method not allowed"}

# A knock is small and fixed in shape; a session review carries one record per
# live session. Two limits rather than one so the cheap route cannot be used
# to make the Controller read a megabyte per knock.
MAX_SPA_VERIFY_BODY = 16 * 1024
MAX_SESSION_REVIEW_BODY = 1024 * 1024

# A posture block names the signals trust_scorer weighs. The count is bounded
# rather than whitelisted: the scorer owns which names mean anything, and a
# name it does not weigh is dropped there, so enforcing a list here would
# only mean editing two files to add a signal.
MAX_POSTURE_SIGNALS = 32

# A string field's ceiling. Nothing in the contract is long, and an unbounded
# string ends up in a log line and in an iptables rule.
MAX_ID_LENGTH = 256
MAX_LABEL_LENGTH = 32

# A connection that opens and sends nothing must not pin a thread for ever.
# This bounds the TLS handshake as well as the request that follows it.
REQUEST_TIMEOUT_SECONDS = 30


class _BadRequest(ValueError):
    """A request this handler refused to read. The message is the reason.

    Private because it never crosses a module boundary: every route catches
    it and turns it into the refusal its own contract specifies.
    """


class ControllerRequestHandler(BaseHTTPRequestHandler):
    """One connection. Created per connection by socketserver; holds no state
    beyond the peer identity it establishes during the handshake."""

    # HTTP/1.1 so a Gateway can keep one connection alive across many knocks -
    # a TLS 1.3 handshake per knock would put the Controller's cost on the
    # critical path of admission. Every response below sets Content-Length,
    # which is what makes keep-alive safe.
    protocol_version = "HTTP/1.1"

    # Do not advertise the Python version: it names the exact interpreter and
    # patch level of the component holding the policy, which is free
    # reconnaissance.
    server_version = "sdp-controller"
    sys_version = ""

    timeout = REQUEST_TIMEOUT_SECONDS

    # Set in handle(), from the VERIFIED peer certificate. Never from a header
    # or a body field.
    gateway_id: str = "unverified"
    peer_subject: str = "unverified"

    @property
    def engine(self) -> PolicyEngine:
        # Set by ControllerServer before the first connection is accepted.
        return self.server.engine  # type: ignore[attr-defined]

    # -- connection --------------------------------------------------------

    def setup(self) -> None:
        super().setup()
        # Applies to the handshake below as well as to reading the request.
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    def handle(self) -> None:
        """Handshake, identify the peer, then serve requests on the connection.

        The handshake runs here, in this connection's own thread, because
        app.ControllerServer wraps the socket with
        ``do_handshake_on_connect=False``. Two things follow:

          * A client whose certificate the project CA did not sign, or that
            presents none at all, fails here and never reaches a route. The
            refusal is the TLS layer's, which is the point of mTLS - no
            application code has to be correct for it to hold.
          * ``gateway_id_from_peer`` then re-reads the verified certificate and
            insists it is a CLIENT certificate with a common name. A
            certificate issued for a server (the IDP's, or this Controller's
            own) is signed by the same CA and would otherwise pass.
        """
        try:
            self.connection.do_handshake()
            der = self.connection.getpeercert(binary_form=True)
            self.gateway_id = cert_utils.gateway_id_from_peer(der)
            self.peer_subject = _subject_text(self.connection.getpeercert())
        except (ssl.SSLError, OSError, ValueError) as exc:
            # ValueError is gateway_id_from_peer's: a verified certificate of
            # the wrong kind. SSLError is an unsigned or absent one.
            status(log, "Connection refused at the TLS layer", peer=self._peer(),
                   error=f"{type(exc).__name__}: {exc}")
            return
        super().handle()

    def handle_one_request(self) -> None:
        # Reset per REQUEST, not per connection: keep-alive means one
        # connection carries several, and _fail() needs to know whether this
        # one has already had bytes written to it.
        self._response_started = False
        super().handle_one_request()

    # -- routing -----------------------------------------------------------

    def do_POST(self) -> None:
        started = time.monotonic()
        # Query and fragment are discarded: no route takes parameters, and
        # comparing the raw self.path would make "/healthz?x=1" a 404.
        path = urlsplit(self.path).path
        self._log_request(path)
        try:
            if path == PATH_SPA_VERIFY:
                self._serve_spa_verify(started)
            elif path == PATH_SESSION_REVIEW:
                self._serve_session_review(started)
            elif path == PATH_HEALTH:
                self._wrong_method(path, "GET, HEAD")
            else:
                self._refuse(HTTPStatus.NOT_FOUND, BODY_NOT_FOUND, path, "no such route")
        except Exception:
            # Never let a bug become an unanswered connection or a traceback
            # on the wire. On /spa_verify the answer is still a denial.
            self._fail(path)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self._log_request(path)
        try:
            if path == PATH_HEALTH:
                self._write_json(HTTPStatus.OK, BODY_HEALTHY)
            elif path in (PATH_SPA_VERIFY, PATH_SESSION_REVIEW):
                self._wrong_method(path, "POST")
            else:
                self._refuse(HTTPStatus.NOT_FOUND, BODY_NOT_FOUND, path, "no such route")
        except Exception:
            self._fail(path)

    # HEAD runs the GET path and _write_json suppresses the body, so a probe
    # gets the same status and headers with nothing after them.
    do_HEAD = do_GET

    def _wrong_method(self, path: str, allow: str) -> None:
        """A route that exists, asked with a verb it does not serve.

        405 with ``Allow``, not 404: RFC 9110 requires the header, and
        answering 404 would tell a Gateway whose client has the verb wrong
        that the Controller is the wrong version.
        """
        self._refuse(HTTPStatus.METHOD_NOT_ALLOWED, BODY_METHOD_NOT_ALLOWED, path,
                     f"{path} does not serve {self.command}",
                     extra_headers={"Allow": allow})

    def _method_not_allowed(self) -> None:
        path = urlsplit(self.path).path
        self._log_request(path)
        self._refuse(HTTPStatus.METHOD_NOT_ALLOWED, BODY_METHOD_NOT_ALLOWED, path,
                     f"method {self.command} is not served",
                     extra_headers={"Allow": "GET, POST"})

    # Spelled out one by one rather than hooked into BaseHTTPRequestHandler's
    # dispatch, so the served verbs stay explicit. An unlisted method gets
    # http.server's own 501, which is also a refusal.
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_OPTIONS = _method_not_allowed

    # -- POST /spa_verify --------------------------------------------------

    def _serve_spa_verify(self, started: float) -> None:
        """Decide one verified knock. The reply is APPROVED or DENIED, never
        an absence of either."""
        try:
            body = self._read_body(MAX_SPA_VERIFY_BODY)
            request = _parse_spa_verify(body)
        except _BadRequest as exc:
            self._deny(HTTPStatus.BAD_REQUEST, f"malformed SPA_VERIFY: {exc}")
            return

        status(log, "SPA_VERIFY received", gateway=self.gateway_id,
               client_ip=request["client_ip"], sid=request["sid"],
               ticket=request["ticket_id"] or "none",
               port=request["access_port"], protocol=request["protocol"],
               posture=",".join(n for n, held in request["posture"].items() if held) or "none")

        try:
            decision = self.engine.decide(
                client_ip=request["client_ip"], access_port=request["access_port"],
                protocol=request["protocol"], sid=request["sid"],
                posture=request["posture"], received_at=request["received_at"])
        except Exception as exc:
            # Fail closed. A decision that could not be computed is not an
            # approval, and the Gateway is owed an answer rather than a
            # timeout - it would deny either way, but only one of the two
            # leaves a reason in the log.
            self._log_traceback("Policy engine raised while deciding a knock",
                                gateway=self.gateway_id, sid=request["sid"])
            self._deny(HTTPStatus.INTERNAL_SERVER_ERROR,
                       f"policy engine failed: {type(exc).__name__}")
            return

        self._log_decision(decision, request, started)

        if not decision.approved:
            self._write_json(HTTPStatus.OK,
                             {"type": TYPE_DENIED, "reason": decision.reason or "denied by policy"})
            return

        inconsistency = _grant_inconsistency(decision)
        if inconsistency is not None:
            # An approval the enforcement layer cannot express is not a grant.
            # Saying so here is the difference between a logged refusal and a
            # knock the Gateway drops with nothing to explain it.
            status(log, "DENIED - approval could not be turned into a grant",
                   gateway=self.gateway_id, sid=request["sid"], reason=inconsistency)
            self._write_json(HTTPStatus.OK,
                             {"type": TYPE_DENIED, "reason": inconsistency})
            return

        session_id = str(uuid.uuid4())
        status(log, "APPROVED", gateway=self.gateway_id, session=session_id[:8],
               client_ip=request["client_ip"], sid=request["sid"], score=decision.score,
               acl=decision.acl, hosts=",".join(decision.allowed_hosts) or "any",
               ttl=f"{decision.ttl_seconds}s", elapsed_ms=f"{_elapsed_ms(started):.1f}")
        self._write_json(HTTPStatus.OK, {
            "type": TYPE_APPROVED,
            "session_id": session_id,
            # Echoed from the request, not re-derived: the Gateway opens the
            # hole it asked about, and a mismatch here would be a hole nobody
            # requested.
            "access_port": request["access_port"],
            "protocol": request["protocol"],
            "ttl_seconds": decision.ttl_seconds,
            "acl": decision.acl,
            "allowed_hosts": list(decision.allowed_hosts),
        })

    def _log_decision(self, decision: Decision, request: dict, started: float) -> None:
        """One line for the score and its sub-scores, then the engine's notes.

        Read defensively (``.get``) because breakdown is documented as
        "posture/suricata/ml sub-scores plus notes" and is the engine's to
        shape; a missing key must not turn a decision into a 500.
        """
        breakdown = decision.breakdown if isinstance(decision.breakdown, dict) else {}
        status(log, "Trust score computed", gateway=self.gateway_id, sid=request["sid"],
               client_ip=request["client_ip"], score=f"{decision.score}/100",
               posture=breakdown.get("posture", "?"), suricata=breakdown.get("suricata", "?"),
               ml=breakdown.get("ml", "?"), acl=decision.acl,
               elapsed_ms=f"{_elapsed_ms(started):.1f}")
        notes = breakdown.get("notes")
        if isinstance(notes, (list, tuple)):
            for note in notes:
                status(log, f"  trust | {note}")

    # -- POST /session_review ----------------------------------------------

    def _serve_session_review(self, started: float) -> None:
        """Re-decide the Gateway's live sessions and name the ones to revoke.

        This is what separates Zero Trust from authorise-once: a grant made at
        admission reflects the evidence of that instant, and the evidence then
        changes. The Gateway owns the session table and the revocation; the
        Controller only says which leases no longer hold.

        An unreadable request is a 400 of type ERROR rather than an empty
        REVIEW_RESULT. The distinction is the whole safety property on this
        route: the Gateway counts consecutive failures and eventually revokes
        everything, whereas an empty revoke list reads as "all of these are
        still fine" and would silently degrade the system to authorise-once.
        """
        try:
            body = self._read_body(MAX_SESSION_REVIEW_BODY)
            sessions = _parse_session_review(body)
        except _BadRequest as exc:
            self._refuse(HTTPStatus.BAD_REQUEST,
                         {"type": TYPE_ERROR, "reason": f"malformed SESSION_REVIEW: {exc}"},
                         PATH_SESSION_REVIEW, str(exc))
            return

        status(log, "SESSION_REVIEW received", gateway=self.gateway_id, sessions=len(sessions))

        try:
            revoke = _normalise_revocations(self.engine.review(sessions))
        except Exception as exc:
            self._log_traceback("Policy engine raised while reviewing sessions",
                                gateway=self.gateway_id, sessions=len(sessions))
            self._refuse(HTTPStatus.INTERNAL_SERVER_ERROR,
                         {"type": TYPE_ERROR, "reason": f"policy engine failed: {type(exc).__name__}"},
                         PATH_SESSION_REVIEW, str(exc))
            return

        for item in revoke:
            status(log, "REVOKE", gateway=self.gateway_id, session=item["session_id"][:8],
                   sid=item["sid"], reason=item["reason"] or "no longer passes policy")
        status(log, "Review complete", gateway=self.gateway_id, checked=len(sessions),
               revoke=len(revoke), elapsed_ms=f"{_elapsed_ms(started):.1f}")
        self._write_json(HTTPStatus.OK, {"type": TYPE_REVIEW_RESULT, "revoke": revoke})

    # -- request reading ---------------------------------------------------

    def _read_body(self, limit: int) -> dict:
        """The request body as a JSON object, or _BadRequest saying why not.

        Content-Length is required and bounded. Chunked bodies are refused
        rather than mis-read: http.server does not decode them, so without
        this the framing bytes would be parsed as JSON and the next request on
        a kept-alive connection would start mid-stream.
        """
        if self.headers.get("Transfer-Encoding"):
            raise _BadRequest("chunked bodies are not accepted; send Content-Length")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise _BadRequest("no Content-Length")
        try:
            length = int(raw_length)
        except ValueError:
            raise _BadRequest(f"Content-Length is not a number: {raw_length!r}") from None
        if not 0 < length <= limit:
            raise _BadRequest(f"Content-Length {length} outside 1..{limit}")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise _BadRequest("body shorter than Content-Length")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise _BadRequest(f"body is not JSON: {exc}") from None
        if not isinstance(body, dict):
            raise _BadRequest(f"body is a JSON {type(body).__name__}, not an object")
        return body

    # -- responses ---------------------------------------------------------

    def _deny(self, code: HTTPStatus, reason: str) -> None:
        """Refuse a knock. The status code says what went wrong; the body says
        DENIED, because that is the only thing the Gateway needs to agree on."""
        status(log, "DENIED", gateway=self.gateway_id, subject=self.peer_subject,
               peer=self._peer(), code=int(code), reason=reason)
        self._write_json(code, {"type": TYPE_DENIED, "reason": reason})

    def _refuse(self, code: HTTPStatus, body: dict, path: str, reason: str,
                extra_headers: dict[str, str] | None = None) -> None:
        """Refuse anything that is not a knock, and log the real reason."""
        status(log, "Refused", gateway=self.gateway_id, subject=self.peer_subject,
               peer=self._peer(), request=f"{self.command} {path}", code=int(code),
               reason=reason)
        self._write_json(code, body, extra_headers=extra_headers)

    def _fail(self, path: str) -> None:
        """An unexpected exception. Logged in full, answered with a sentence.

        On /spa_verify the sentence is a denial: a request whose handling
        raised has not been approved, and the reply must not be ambiguous
        about that.
        """
        self._log_traceback("Request handler raised", gateway=self.gateway_id,
                            request=f"{self.command} {path}")
        if self._response_started:
            # Headers, and possibly part of a body, are already on the wire, so
            # a second response would corrupt the stream. Drop the connection
            # and let the Gateway see a truncated reply - which it treats as a
            # failure, which is a denial.
            self.close_connection = True
            return
        body = ({"type": TYPE_DENIED, "reason": "controller error"} if path == PATH_SPA_VERIFY
                else {"type": TYPE_ERROR, "reason": "controller error"})
        try:
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, body)
        except OSError:
            self.close_connection = True

    def _write_json(self, code: HTTPStatus, payload: dict,
                    extra_headers: dict[str, str] | None = None) -> None:
        # Keys keep the order of the dict literal they were written in: the
        # body shape is a contract shared with the Gateway.
        raw = json.dumps(payload).encode("utf-8")
        self._response_started = True
        self.send_response(int(code))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        # Nothing here is cacheable. A cached APPROVED would be a grant
        # replayed to the next caller.
        self.send_header("Cache-Control", "no-store")
        # Any refusal ends the connection, and says so.
        #
        # A 400, 404, 405 or 500 is answered without having consumed the
        # request body - either because the body is what was wrong with it, or
        # because the route was never reached. Those unread bytes sit in a
        # kept-alive connection and are then parsed as the NEXT request line,
        # so one malformed knock turns the rest of the connection into
        # nonsense and the Gateway's following knocks are refused for reasons
        # that have nothing to do with them. Closing costs a TLS handshake on
        # an error path that should be rare; the alternative silently corrupts
        # the good path. A policy denial is a 200 and keeps the connection, so
        # the ordinary deny is still cheap. (stdlib send_header sets
        # close_connection itself when it sees this header.)
        if int(code) >= 400:
            self.send_header("Connection", "close")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        # A HEAD response carries the same headers and no body. Writing one
        # anyway would leave unread bytes in a kept-alive connection and
        # desynchronise the next request on it.
        if self.command != "HEAD":
            self.wfile.write(raw)

    # -- plumbing ----------------------------------------------------------

    def _log_request(self, path: str) -> None:
        """Every request, with the identity the certificate proved.

        Deliberately before any parsing, so a request that is about to be
        refused is still attributed to a Gateway. One Controller serves
        several Gateways; "a knock was denied" is not actionable without
        knowing which one asked.
        """
        status(log, "Request", gateway=self.gateway_id, subject=self.peer_subject,
               peer=self._peer(), request=f"{self.command} {path}")

    def _log_traceback(self, step: str, **fields: Any) -> None:
        status(log, step, peer=self._peer(), **fields)
        for line in traceback.format_exc().rstrip().splitlines():
            log.error("    %s", line)

    def _peer(self) -> str:
        try:
            return self.client_address[0]
        except (AttributeError, IndexError):
            return "unknown"

    def version_string(self) -> str:
        # BaseHTTPRequestHandler joins server_version and sys_version with a
        # space, which with sys_version blanked leaves a trailing one in the
        # Server header. Returning the name alone also guarantees the Python
        # version cannot creep back in through a subclass.
        return self.server_version

    def log_message(self, fmt: str, *args) -> None:
        """Silence http.server's own access line - _log_request carries more,
        in the format the rest of the project uses. Kept at debug so it can be
        turned back on by lowering the logger level."""
        log.debug(fmt, *args)

    def log_error(self, fmt: str, *args) -> None:
        """Refusals http.server makes before any route is chosen: an over-long
        request line, too many headers, an unparseable version. These never
        reach do_POST, so without this they would be refused silently."""
        detail = fmt % args if args else fmt
        status(log, "Malformed request refused before routing", peer=self._peer(),
               gateway=self.gateway_id, detail=detail)


# --------------------------------------------------------------------------- #
# Parsing. Module-level functions, not methods: they touch no connection      #
# state, which makes them readable on their own and testable without a socket.#
# --------------------------------------------------------------------------- #

def _parse_spa_verify(body: dict) -> dict:
    """Validate a SPA_VERIFY and return exactly what decide() needs.

    Strict about types rather than forgiving: the Controller is the component
    that says yes, so a field it had to guess at is a field it should refuse.

    ``received_at`` IS forwarded. policies.yaml has time-of-day rules
    (mfa-off-hours), so the hour a decision is scored against is part of the
    verdict. Scoring on the Controller's own processing clock instead would
    make the same knock decide differently in-process and remotely whenever
    it crossed an hour boundary, and would drift further the moment the two
    hosts' clocks did. The Gateway presented a CA-signed certificate to get
    here, so its timestamp is exactly as trustworthy as the rest of the
    message it sent.

    ``wg_public_key`` is validated and dropped: the engine takes no key.
    """
    _require_type(body, TYPE_SPA_VERIFY)
    identity = body.get("identity")
    if not isinstance(identity, dict):
        raise _BadRequest("identity is missing or not an object")

    received_at = _optional_timestamp(body, "received_at")
    ticket_id = _optional_string(identity, "ticket_id", MAX_ID_LENGTH)
    _optional_string(identity, "wg_public_key", MAX_ID_LENGTH)

    return {
        "client_ip": _client_ip(body, "client_ip"),
        "access_port": _port(body, "access_port"),
        "protocol": _protocol(body, "protocol"),
        "sid": _string(identity, "sid", MAX_ID_LENGTH),
        "posture": _posture(identity),
        "ticket_id": ticket_id,
        "received_at": received_at,
    }


def _parse_session_review(body: dict) -> list[dict]:
    """Validate a SESSION_REVIEW into the session list review() expects.

    One malformed record fails the whole request rather than being skipped.
    Skipping it would drop a session from the review silently, and a session
    that was not reviewed is a session that keeps its access - the one outcome
    this route exists to prevent.
    """
    _require_type(body, TYPE_SESSION_REVIEW)
    raw_sessions = body.get("sessions")
    if not isinstance(raw_sessions, list):
        raise _BadRequest("sessions is missing or not an array")

    sessions: list[dict] = []
    for index, raw in enumerate(raw_sessions):
        if not isinstance(raw, dict):
            raise _BadRequest(f"sessions[{index}] is not an object")
        try:
            sessions.append({
                "session_id": _string(raw, "session_id", MAX_ID_LENGTH),
                "sid": _string(raw, "sid", MAX_ID_LENGTH),
                "client_ip": _client_ip(raw, "client_ip"),
                "access_port": _port(raw, "access_port"),
                "protocol": _protocol(raw, "protocol"),
                # Not checked against FULL/LIMITED/DENY on purpose: a Gateway
                # that grows a new ACL width must not make every review a 400,
                # because enough consecutive 400s revoke every live session.
                "acl": _string(raw, "acl", MAX_LABEL_LENGTH),
                "posture": _posture(raw),
            })
        except _BadRequest as exc:
            raise _BadRequest(f"sessions[{index}]: {exc}") from None
    return sessions


def _normalise_revocations(revoke: Any) -> list[dict]:
    """The engine's revocation list, reduced to the three keys on the wire.

    Rebuilt rather than forwarded so the reply shape is owned by this module
    and no engine-internal field leaks onto the link. A malformed entry raises
    rather than being dropped: the caller turns that into an ERROR, and the
    Gateway's failure counter handles it. Dropping it would leave a session
    open that the engine said to close.
    """
    if not isinstance(revoke, list):
        raise ValueError(f"review() returned a {type(revoke).__name__}, not a list")
    out: list[dict] = []
    for index, item in enumerate(revoke):
        if not isinstance(item, dict):
            raise ValueError(f"review()[{index}] is a {type(item).__name__}, not a dict")
        try:
            session_id = _string(item, "session_id", MAX_ID_LENGTH)
            sid = _string(item, "sid", MAX_ID_LENGTH)
        except _BadRequest as exc:
            raise ValueError(f"review()[{index}]: {exc}") from None
        reason = item.get("reason")
        out.append({"session_id": session_id, "sid": sid,
                    "reason": reason if isinstance(reason, str) else ""})
    return out


def _grant_inconsistency(decision: Decision) -> str | None:
    """Why an approved Decision cannot be issued as a grant, or None.

    Not a second policy layer - it chooses nothing. It catches the two shapes
    the Gateway's firewall cannot express, which would otherwise become a
    knock that is approved here and dropped there with nothing in either log
    to connect the two. ``allowed_hosts == ()`` is NOT one of them: the
    contract defines the empty tuple as "any destination".
    """
    if decision.acl not in (ACL_FULL, ACL_LIMITED):
        return f"approved with acl={decision.acl!r}, which grants nothing"
    if not isinstance(decision.ttl_seconds, int) or decision.ttl_seconds <= 0:
        return f"approved with ttl_seconds={decision.ttl_seconds!r}, which expires immediately"
    return None


def _require_type(body: dict, expected: str) -> None:
    found = body.get("type")
    if found != expected:
        raise _BadRequest(f"type is {found!r}, expected {expected!r}")


def _string(obj: dict, key: str, limit: int) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _BadRequest(f"{key} is missing or not a non-empty string")
    if len(value) > limit:
        raise _BadRequest(f"{key} is longer than {limit} characters")
    return value


def _optional_string(obj: dict, key: str, limit: int) -> str:
    if obj.get(key) is None:
        return ""
    return _string(obj, key, limit)


def _client_ip(obj: dict, key: str) -> str:
    """An address the engine can look up in the telemetry snapshot.

    Parsed with ipaddress rather than taken as text: the source IP is one of
    the inputs to the score, and a value that is not an address cannot match
    any telemetry entry, so accepting one would quietly score the knock as if
    the detection pipeline had never seen it.
    """
    value = _string(obj, key, MAX_ID_LENGTH)
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise _BadRequest(f"{key} is not an IP address: {exc}") from None
    return value


def _port(obj: dict, key: str) -> int:
    value = obj.get(key)
    # bool is an int in Python, and True would silently become port 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise _BadRequest(f"{key} is missing or not an integer")
    if not 1 <= value <= 65535:
        raise _BadRequest(f"{key} out of range: {value}")
    return value


def _protocol(obj: dict, key: str) -> str:
    """A protocol label the Gateway will put in a firewall rule.

    Restricted to alphanumerics, not to a whitelist of tcp/udp: naming the
    allowed protocols is the Gateway's and the policy's business, while
    keeping punctuation out of a value that ends up in a rule and in a log
    line is this module's.
    """
    value = _string(obj, key, MAX_LABEL_LENGTH)
    if not value.isalnum():
        raise _BadRequest(f"{key} is not alphanumeric: {value!r}")
    return value


def _posture(obj: dict) -> dict[str, bool]:
    """The posture block, or {} when there is none.

    An absent block is not an error. It means a client or IDP older than
    knock-ticket version 2, and the scorer's own convention is that an
    unknown signal is an untrusted one - so the knock degrades to a low score
    and a denial rather than to a 400 the Gateway cannot act on.

    A present block is strict: a non-bool value is refused rather than read as
    truthy. "disk_encrypted": "false" is a string, and a truthiness test would
    credit it.
    """
    posture = obj.get("posture")
    if posture is None:
        return {}
    if not isinstance(posture, dict):
        raise _BadRequest("posture is not an object")
    if len(posture) > MAX_POSTURE_SIGNALS:
        raise _BadRequest(f"posture names more than {MAX_POSTURE_SIGNALS} signals")
    out: dict[str, bool] = {}
    for name, value in posture.items():
        if not isinstance(name, str) or not name:
            raise _BadRequest("posture has a signal with no name")
        if not isinstance(value, bool):
            raise _BadRequest(f"posture[{name!r}] is {type(value).__name__}, not a boolean")
        out[name] = value
    return out


def _optional_timestamp(obj: dict, key: str) -> float | None:
    value = obj.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _BadRequest(f"{key} is not a number")
    if value < 0:
        raise _BadRequest(f"{key} is negative")
    return float(value)


def _subject_text(cert: dict | None) -> str:
    """The peer certificate's subject as "commonName=gw-1", for a log line.

    ssl parses the subject into nested tuples of (name, value) pairs. Flattened
    here rather than shown raw because this string is read by an operator
    scanning for which Gateway asked.
    """
    if not cert:
        return "no subject"
    parts = [f"{name}={value}"
             for rdn in cert.get("subject", ()) for name, value in rdn]
    return ",".join(parts) or "no subject"


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0
