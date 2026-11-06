"""The two routes this node exposes, and deliberately nothing else.

    GET /api/data   Authorization: Bearer <access_token>
                    -> 200 {"resource": ..., "served_at": <unix int>, "subject": ...}
    GET /healthz    no credentials
                    -> 200 {"status": "ok"}

Everything else is 404, and every method other than GET is 405. The surface
is this small on purpose: the resource node is the most exposed component in
the topology — the one thing a compromised client that got through the
Gateway is talking to — so there is no file serving, no directory listing, no
body parsing and no reflection of request content into a response.

Two decisions are worth stating outright.

**A 401 says nothing.** The body is a fixed ``{"error": "unauthorized"}`` for
a missing header, a forged signature, an expired token and a token minted for
the Gateway alike. The real reason goes to the audit line. An error body that
distinguishes "bad signature" from "expired" hands an attacker a free oracle
for probing which part of a stolen credential is still good.

**/healthz is unauthenticated but says nothing either.** Docker's healthcheck
and the Gateway's reachability probe both need it to work before any token
exists, so it cannot require one. In exchange it reports a constant: no
version, no uptime, no subject, nothing that changes with internal state.

A 401 carries ``WWW-Authenticate: Bearer`` because RFC 7235 requires a
challenge on a 401, with no ``realm`` or ``error`` parameter so the header
leaks no more than the status code already does.
"""

from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from access.guard import AUTH_HEADER, TokenAuthority, authorize
from access.session_validator import TokenRejected
from monitor import audit
from shared.utils.logger import get_logger, status

log = get_logger("Res-HTTP")

PATH_DATA = "/api/data"
PATH_HEALTH = "/healthz"

# Fixed response bodies. Module constants rather than literals at the call
# site so it stays obvious that no request-derived text ever reaches them.
BODY_UNAUTHORIZED = {"error": "unauthorized"}
BODY_NOT_FOUND = {"error": "not found"}
BODY_METHOD_NOT_ALLOWED = {"error": "method not allowed"}
BODY_INTERNAL = {"error": "internal error"}
BODY_HEALTHY = {"status": "ok"}

# A connection that opens and then sends nothing must not pin a thread for
# ever. socketserver applies this to the socket, and http.server turns the
# resulting timeout into a closed connection.
REQUEST_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class ResourceContext:
    """What the handler needs, resolved once at startup and never rebound.

    Held on the server object and read by every handler thread. Frozen, so a
    thread-per-connection server needs no lock around it.
    """

    name: str
    authority: TokenAuthority


class ResourceRequestHandler(BaseHTTPRequestHandler):
    """One request. Created per request by socketserver; holds no state."""

    # HTTP/1.1 so the Gateway can keep the inner connection alive between
    # forwarded requests. Every response below sets Content-Length, which is
    # what makes that safe — without it http.server would have to close the
    # connection after each response to delimit the body.
    protocol_version = "HTTP/1.1"

    # Do not advertise the Python version. It names the exact interpreter and
    # patch level to anyone who asks, which is free reconnaissance.
    server_version = "resource-node"
    sys_version = ""

    timeout = REQUEST_TIMEOUT_SECONDS

    @property
    def context(self) -> ResourceContext:
        # Set by ResourceServer before the first request is accepted.
        return self.server.context  # type: ignore[attr-defined]

    # -- routing -----------------------------------------------------------

    def handle_one_request(self) -> None:
        # Reset per REQUEST, not per connection: HTTP/1.1 keep-alive means one
        # connection carries several, and _fail() needs to know whether this
        # one has already had bytes written to it.
        self._response_started = False
        super().handle_one_request()

    def do_GET(self) -> None:
        started = time.monotonic()
        # Query and fragment are discarded: neither route takes parameters,
        # and comparing the raw self.path would make "/healthz?x=1" a 404.
        path = urlsplit(self.path).path
        try:
            if path == PATH_HEALTH:
                self._serve_health(path, started)
            elif path == PATH_DATA:
                self._serve_data(path, started)
            else:
                self._refuse(HTTPStatus.NOT_FOUND, BODY_NOT_FOUND, path,
                             reason="no such route", started=started)
        except Exception:
            # Never let a bug become an unanswered connection or a traceback
            # on the wire. The stack goes to the log; the client gets five
            # words.
            self._fail(path, started)

    def _method_not_allowed(self) -> None:
        started = time.monotonic()
        path = urlsplit(self.path).path
        self._refuse(HTTPStatus.METHOD_NOT_ALLOWED, BODY_METHOD_NOT_ALLOWED, path,
                     reason=f"method {self.command} is not served", started=started,
                     extra_headers={"Allow": "GET"})

    # HEAD runs the GET path and _write_json suppresses the body, so a probe
    # gets the same status and headers with nothing after them. RFC 9110
    # requires HEAD wherever GET is served, and a health probe that uses it
    # must not meet a 405 from the one endpoint that exists to answer probes.
    do_HEAD = do_GET

    # The rest are spelled out one by one rather than hooked into
    # BaseHTTPRequestHandler's dispatch: an unlisted method gets
    # http.server's own 501, which is also a refusal, and listing these keeps
    # the served verbs explicit.
    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_OPTIONS = _method_not_allowed

    # -- routes ------------------------------------------------------------

    def _serve_health(self, path: str, started: float) -> None:
        """Liveness only. No credentials required, no internal state leaked."""
        self._write_json(HTTPStatus.OK, BODY_HEALTHY)
        audit.record(peer=self._peer(), method=self.command, path=path,
                     decision=audit.ALLOW, status_code=int(HTTPStatus.OK),
                     reason="healthz requires no credentials",
                     elapsed_ms=self._elapsed_ms(started))

    def _serve_data(self, path: str, started: float) -> None:
        """The protected resource. Offline token validation gates it."""
        try:
            claims = authorize(self.context.authority, self.headers.get(AUTH_HEADER))
        except TokenRejected as exc:
            self._refuse(HTTPStatus.UNAUTHORIZED, BODY_UNAUTHORIZED, path,
                         reason=exc.reason, started=started,
                         extra_headers={"WWW-Authenticate": "Bearer"})
            return

        subject = claims.get("sub")
        body = {
            "resource": self.context.name,
            "served_at": int(time.time()),
            "subject": subject,
        }
        self._write_json(HTTPStatus.OK, body)
        audit.record(peer=self._peer(), method=self.command, path=path,
                     decision=audit.ALLOW, status_code=int(HTTPStatus.OK),
                     subject=subject, sid=claims.get("sid"), jti=claims.get("jti"),
                     elapsed_ms=self._elapsed_ms(started))

    # -- responses ---------------------------------------------------------

    def _refuse(self, code: HTTPStatus, body: dict, path: str, *, reason: str,
                started: float, extra_headers: dict[str, str] | None = None) -> None:
        """Deny, record the real reason, and send the generic one."""
        self._write_json(code, body, extra_headers=extra_headers)
        audit.record(peer=self._peer(), method=self.command, path=path,
                     decision=audit.DENY, status_code=int(code), reason=reason,
                     elapsed_ms=self._elapsed_ms(started))

    def _fail(self, path: str, started: float) -> None:
        """An unexpected exception. Logged in full, answered with nothing."""
        status(log, "Request handler raised", peer=self._peer(),
               request=f"{self.command} {path}")
        for line in traceback.format_exc().rstrip().splitlines():
            log.error("    %s", line)
        if self._response_started:
            # Headers (and possibly part of a body) are already on the wire,
            # so a second response would corrupt the stream. Drop the
            # connection instead and let the client see a truncated reply.
            self.close_connection = True
        else:
            try:
                self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, BODY_INTERNAL)
            except OSError:
                # The client is already gone. The audit line is still owed.
                self.close_connection = True
        audit.record(peer=self._peer(), method=self.command, path=path,
                     decision=audit.DENY,
                     status_code=int(HTTPStatus.INTERNAL_SERVER_ERROR),
                     reason="unhandled exception in handler",
                     elapsed_ms=self._elapsed_ms(started))

    def _write_json(self, code: HTTPStatus, payload: dict,
                    extra_headers: dict[str, str] | None = None) -> None:
        # Keys keep the order of the dict literal they were written in: the
        # body shape is a contract shared with the client and the Gateway.
        raw = json.dumps(payload).encode("utf-8")
        self._response_started = True
        self.send_response(int(code))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        # Nothing served here is cacheable: /api/data carries a timestamp and
        # a subject, and a cached 200 in front of this node would hand one
        # subject's response to the next caller.
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        # A HEAD response must carry the same headers and no body. Writing one
        # anyway would leave unread bytes in a kept-alive connection and
        # desynchronise the next request on it.
        if self.command != "HEAD":
            self.wfile.write(raw)

    # -- plumbing ----------------------------------------------------------

    def _peer(self) -> str:
        # Always the Gateway in the intended topology. See monitor/audit.py.
        try:
            return self.client_address[0]
        except (AttributeError, IndexError):
            return "unknown"

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return (time.monotonic() - started) * 1000.0

    def version_string(self) -> str:
        # BaseHTTPRequestHandler joins server_version and sys_version with a
        # space, which with sys_version blanked leaves a trailing one in the
        # Server header. Returning the name alone also guarantees the Python
        # version cannot creep back in through a subclass.
        return self.server_version

    def log_message(self, fmt: str, *args) -> None:
        """Silence http.server's own access line.

        It goes to stderr in a format nothing else here uses, and it would
        duplicate the audit trail, which carries strictly more. Kept at debug
        so it can be turned back on by raising the logger level.
        """
        log.debug(fmt, *args)

    def log_error(self, fmt: str, *args) -> None:
        """Refusals http.server makes before any route is chosen.

        An over-long request line, too many headers, an unparseable version.
        These never reach do_GET, so without this they would be refused
        silently.
        """
        detail = fmt % args if args else fmt
        status(log, "Malformed request refused before routing",
               peer=self._peer(), detail=detail)
