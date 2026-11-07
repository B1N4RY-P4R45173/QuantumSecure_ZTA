"""The Gateway's side of the Gateway <-> Controller link, over mutual TLS.

WHY THIS EXISTS
    The access decision does not belong in the Gateway. While it runs in
    process (controller/policy_controller.py) the Gateway is both the policy
    enforcement point and the policy decision point: every Gateway in a fleet
    needs policies.yaml, the telemetry snapshot and the ML model on its own
    disk, and an operator who tightens a rule has to tighten it on each box.
    This class moves the decision to one Controller service and leaves the
    Gateway doing only what it is positioned to do, which is enforce. It
    implements the same one-method seam as the in-process controllers
    (controller/client.ControllerClient), so spa/listener.py cannot tell which
    side of the wire decided - and that is the point: the enforcement path is
    identical either way, so moving the decision out changes where policy
    lives, not how a knock is handled.

WHICH END DIALS, AND WHY
    The Gateway opens every connection; the Controller never calls in. That is
    the same rule as the IDP link (mtls/idp_link.py) and it is deliberate.
    Every inbound control connection in the system then terminates on one side
    of it, so this Gateway needs no listening control port beyond the SPA
    port, and the Controller can sit behind a firewall that permits nothing
    inbound from the data plane at all. Revocation still crosses the wire,
    because the Gateway asks for it (see reevaluate) rather than being told.

FAIL CLOSED, IN TWO DIFFERENT DIRECTIONS
    A knock and a live session fail closed differently, and treating them
    alike would be a bug whichever way round it was made.

    /spa_verify      No answer means no decision, and no decision means no
                     admission. Transport failure, TLS failure, HTTP error,
                     a body that is not JSON, an APPROVED the Gateway cannot
                     act on - all of them become DENIED. There is deliberately
                     no fallback to the in-process engine and no cached
                     approval: either the Controller approved this knock just
                     now, or the knock is refused.

    /session_review  Revoking on the first failed pass would turn one dropped
                     packet into an outage, cutting every live session because
                     an HTTP request timed out. So consecutive failures are
                     counted, each one logged loudly, and only once
                     GATEWAY_REVIEW_FAILURES_BEFORE_REVOKE of them land in a
                     row is everything revoked. The counter is only ever
                     counting consecutive passes in which a grant nobody
                     re-authorised was left standing, so it resets on a pass
                     that succeeds and on a pass with nothing left to review.
                     What this must never do is fail quietly: a Controller
                     that stays down has to end in closed sessions, not in a
                     Gateway that has silently degraded to authorise-once
                     while still looking healthy.

CERTIFICATES
    The Gateway presents the same gateway.crt / gateway.key it already
    presents to the IDP. That is one Gateway identity rather than one per
    peer, and it is the identity the project CA issued, so the Controller
    authorises the Gateway on exactly the evidence the IDP does. The
    Controller is verified against ca.crt and its certificate must name the
    host in GATEWAY_CONTROLLER_URL, so a reachable impostor is not a
    Controller.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

# This module is reached as `controller.remote`, i.e. with SDP_GATEWAY as the
# import root; it needs `firewall` from that root and `shared` from the repo
# root one level above. main.py puts both on sys.path - repeating it here keeps
# the module importable on its own and under pytest, instead of depending on
# whichever entrypoint got there first.
_COMPONENT_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _COMPONENT_ROOT.parent
for _path in (_REPO_ROOT, _COMPONENT_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from firewall.sessions import TABLE  # noqa: E402
from shared.ca import cert_utils  # noqa: E402
from shared.config.settings import settings  # noqa: E402
from shared.utils.logger import get_logger, status  # noqa: E402

log = get_logger("Controller")

# Where the Controller listens. Unset means the Gateway decides in process;
# main.py owns that choice, this module only supplies the default so the two
# cannot disagree about which variable names the link.
CONTROLLER_URL = os.environ.get("GATEWAY_CONTROLLER_URL", "").strip()

SPA_VERIFY_PATH = "/spa_verify"
SESSION_REVIEW_PATH = "/session_review"
HEALTHZ_PATH = "/healthz"

# Short on purpose, and the same for connect and read: the SPA listener blocks
# on /spa_verify, so a hung Controller would otherwise hold up every knock
# queued behind it. A Controller that cannot answer in a few seconds is a
# Controller that is not answering, and a denial now beats a stall.
TIMEOUT_SECONDS = float(os.environ.get("GATEWAY_CONTROLLER_TIMEOUT_SECONDS", "3"))

# How many consecutive failed review passes are tolerated before every live
# session is revoked. A security parameter rather than a tuning knob: it is the
# window in which the Gateway keeps enforcing grants that nobody is
# re-authorising. Three passes at main.py's default 10s interval is about half
# a minute of blind enforcement.
FAILURES_BEFORE_REVOKE = int(os.environ.get("GATEWAY_REVIEW_FAILURES_BEFORE_REVOKE", "3"))


class ControllerLinkNotConfigured(RuntimeError):
    pass


def ssl_context() -> ssl.SSLContext:
    """The Gateway's client context for the Controller link.

    Same bundle as mtls/idp_link.ssl_context(): one Gateway identity, two
    peers. Missing files are named rather than left to surface as a
    load_cert_chain traceback, because the fix is an operator action.
    """
    paths = {"certificate": settings.gateway_tls_cert_path,
             "private key": settings.gateway_tls_key_path,
             "CA certificate": settings.gateway_ca_cert_path}
    missing = [f"{what} ({p})" for what, p in paths.items() if not Path(p).exists()]
    if missing:
        raise ControllerLinkNotConfigured(
            "Gateway certificate bundle missing: " + ", ".join(missing)
            + " - on the IDP machine run `admin_cli.py issue-gateway-cert --id <id>`"
              " and copy the folder here as certs/pki/")
    return cert_utils.client_context(settings.gateway_tls_cert_path,
                                     settings.gateway_tls_key_path,
                                     settings.gateway_ca_cert_path)


def _short(value: object, limit: int = 200) -> str:
    """A reply squeezed onto one log line. Only ever used on failure paths."""
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _error_reason(body: str) -> str | None:
    """The `reason` out of an error body, when there is one to read. The
    Controller sends a sentence with its refusals; repeating raw JSON at an
    operator instead would bury it."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("reason"), str):
        return parsed["reason"]
    return None


def _approval_problem(reply: dict, request: dict) -> str | None:
    """Why this APPROVED cannot be acted on, or None when it can.

    Checked here rather than in the listener because the listener indexes
    session_id, access_port, protocol and ttl_seconds straight out of the
    reply to open the hole: a missing or mistyped field has to become a denial
    before anything reaches the packet filter, not a KeyError half way through
    granting access.

    Port and protocol are also checked against the knock. The destination is
    the client's to name and the verdict is the Controller's, so a Controller
    answering about a different port than was knocked for is answering about
    the wrong request, and the Gateway must not open it.
    """
    session_id = reply.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return f"session_id missing or not a string: {reply.get('session_id')!r}"

    ttl = reply.get("ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
        return f"ttl_seconds not a positive number: {ttl!r}"

    try:
        port = int(reply["access_port"])
    except (KeyError, TypeError, ValueError):
        return f"access_port missing or not a port number: {reply.get('access_port')!r}"
    if port != request.get("access_port"):
        return f"access_port {port} is not the knocked port {request.get('access_port')!r}"

    protocol = reply.get("protocol")
    if not isinstance(protocol, str) or \
            protocol.lower() != str(request.get("protocol", "")).lower():
        return f"protocol {protocol!r} is not the knocked protocol {request.get('protocol')!r}"

    hosts = reply.get("allowed_hosts")
    if hosts is not None and not isinstance(hosts, (list, tuple)):
        return f"allowed_hosts is not a list: {type(hosts).__name__}"
    return None


class RemoteController:
    """Decides nothing; asks the Controller and enforces the answer.

    Implements the same `send(msg) -> dict` contract as AllowAllController and
    PolicyController, plus the `reevaluate()` main.py's re-evaluation loop
    looks for, so swapping this in changes where policy is evaluated and
    nothing else.
    """

    def __init__(self, url: str | None = None, *,
                 timeout: float = TIMEOUT_SECONDS,
                 failures_before_revoke: int = FAILURES_BEFORE_REVOKE,
                 context: ssl.SSLContext | None = None) -> None:
        self._url = (url or CONTROLLER_URL).strip().rstrip("/")
        if not self._url:
            raise ControllerLinkNotConfigured(
                "no Controller URL - set GATEWAY_CONTROLLER_URL=https://sdp-controller:9500")
        if not self._url.startswith("https://"):
            # There is no cleartext mode. The whole point of the link is that
            # both ends prove who they are, and http:// would quietly drop the
            # Gateway's certificate along with the Controller's.
            raise ControllerLinkNotConfigured(
                f"Controller URL must be https:// - the link is mutual TLS: {self._url!r}")
        self._timeout = timeout
        # One failure can never be enough to cut every session; see the module
        # docstring. A configured 0 or negative would mean exactly that, so it
        # is floored rather than honoured.
        self._failures_before_revoke = max(1, failures_before_revoke)
        self._ctx = context or ssl_context()
        # Mutated only by the single re-evaluation thread main.py starts, and
        # read nowhere else, so it needs no lock.
        self._review_failures = 0

        status(log, "Controller: remote service over mTLS", url=self._url,
               timeout=f"{self._timeout:g}s",
               revoke_after_failed_reviews=self._failures_before_revoke,
               certificate=settings.gateway_tls_cert_path,
               ca=settings.gateway_ca_cert_path)

    @property
    def url(self) -> str:
        return self._url

    # -- transport ---------------------------------------------------------

    def _request(self, req: urllib.request.Request) -> dict:
        """One round trip. Raises RuntimeError, with a sentence an operator can
        act on, for anything short of a parsed JSON object."""
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # Must come before URLError: HTTPError is a subclass of it.
            #
            # The status code is authoritative, not the body. The Controller
            # answers a malformed /spa_verify with 400 and a DENIED body, and
            # that is still not a decision about this knock - it means the two
            # ends disagree about the wire format - so it raises rather than
            # being passed off as a policy denial. The body's own sentence is
            # carried into the message, because it names what the Controller
            # objected to and nothing else will.
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"Controller answered {exc.code}: "
                               f"{_error_reason(detail) or detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            # urllib wraps TLS failures in URLError, and a certificate problem
            # reads nothing like an unreachable host to whoever has to fix it.
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise RuntimeError(
                    f"Controller certificate not trusted - wrong CA, or {self._url} is not a "
                    f"name it was issued for: {reason}") from exc
            if isinstance(reason, ssl.SSLError):
                raise RuntimeError(
                    f"mTLS with the Controller failed - did it accept this Gateway's "
                    f"certificate? {reason}") from exc
            raise RuntimeError(f"Controller unreachable at {self._url}: {reason}") from exc

        try:
            reply = json.loads(raw)
        except ValueError as exc:
            raise RuntimeError(f"Controller reply is not JSON: {raw[:200]!r}") from exc
        if not isinstance(reply, dict):
            raise RuntimeError(f"Controller reply is not a JSON object: {_short(reply)}")
        return reply

    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        return self._request(urllib.request.Request(
            f"{self._url}{path}", data=body, method="POST",
            headers={"Content-Type": "application/json"}))

    def check_healthz(self) -> dict:
        """Probe the Controller before the SPA port opens.

        Raises RuntimeError with a sentence rather than a traceback, so startup
        can abort the way _check_idp_jwks does. A Gateway whose Controller is
        unreachable can approve nothing, and a SPA port that answers every
        knock with silence is worse than one that was never opened: it looks
        like a working Gateway.
        """
        reply = self._request(urllib.request.Request(f"{self._url}{HEALTHZ_PATH}"))
        if reply.get("status") != "ok":
            raise RuntimeError(f"Controller {HEALTHZ_PATH} is not ok: {_short(reply)}")
        return reply

    # -- the ControllerClient seam ----------------------------------------

    def send(self, msg: dict) -> dict:
        if msg.get("type") != "SPA_VERIFY":
            return {"type": "ERROR", "reason": f"unknown: {msg.get('type')}"}

        client_ip = msg.get("client_ip")
        sid = (msg.get("identity") or {}).get("sid", "unknown")

        try:
            reply = self._post(SPA_VERIFY_PATH, msg)
        except RuntimeError as exc:
            status(log, "DENIED - no decision from the Controller", client_ip=client_ip,
                   sid=sid, url=self._url, error=str(exc))
            return {"type": "DENIED", "reason": f"no decision from the Controller: {exc}"}

        if reply.get("type") != "APPROVED":
            reason = reply.get("reason") or f"Controller answered {reply.get('type')!r}"
            status(log, "DENIED by the remote Controller", client_ip=client_ip, sid=sid,
                   reason=reason)
            return {"type": "DENIED", "reason": str(reason)}

        problem = _approval_problem(reply, msg)
        if problem is not None:
            status(log, "DENIED - malformed APPROVED from the Controller", client_ip=client_ip,
                   sid=sid, problem=problem, reply=_short(reply))
            return {"type": "DENIED", "reason": f"malformed APPROVED: {problem}"}

        acl = str(reply.get("acl") or "FULL").upper()
        hosts = [str(h) for h in (reply.get("allowed_hosts") or ())]
        status(log, "APPROVED by the remote Controller", session=reply["session_id"][:8],
               client_ip=client_ip, sid=sid, acl=acl, hosts=",".join(hosts) or "any",
               ttl=f"{reply['ttl_seconds']}s")
        # Rebuilt rather than forwarded, so only validated fields reach the
        # listener and a stray key on the wire cannot ride along into a grant.
        return {"type": "APPROVED",
                "session_id": reply["session_id"],
                "access_port": int(reply["access_port"]),
                "protocol": str(reply["protocol"]),
                "ttl_seconds": reply["ttl_seconds"],
                "acl": acl,
                "allowed_hosts": hosts}

    # -- continuous re-evaluation ------------------------------------------

    def reevaluate(self) -> list[str]:
        """Ask the Controller which live sessions to close, and close them.

        The in-process controller re-scored sessions itself. Here the evidence
        a re-score needs - Suricata alerts, ML verdicts, policies.yaml - lives
        on the Controller, so what crosses the wire is the live session list
        and what comes back is a revocation list. The Gateway still dials out
        and still owns the packet filter: revocation is an answer it acted on,
        never a connection the Controller made.

        Posture travels with each session because it cannot be re-derived
        here. It arrived attested inside a knock ticket and the admission-time
        value is carried forward (firewall/sessions.Session.posture_signals);
        a device whose posture decays is caught at its next knock, which is a
        real gap and worth stating rather than papering over.

        Returns the session ids actually closed, for the caller to log.
        """
        live = TABLE.active()
        if not live:
            # The counter measures one thing only: how many passes in a row
            # this Gateway has been enforcing grants that nobody re-authorised.
            # With no session standing that number is zero, whatever the
            # Controller is doing, so the streak ends here rather than being
            # carried into the next session's first pass and spending its
            # tolerance before it has had one.
            self._review_failures = 0
            return []

        payload = {"type": "SESSION_REVIEW",
                   "sessions": [{"session_id": s.session_id,
                                 "sid": s.sid,
                                 "client_ip": s.client_ip,
                                 "access_port": s.access_port,
                                 "protocol": s.protocol,
                                 "acl": s.acl,
                                 "posture": dict(s.posture_signals)} for s in live]}

        try:
            reply = self._post(SESSION_REVIEW_PATH, payload)
            revoke = reply.get("revoke")
            if reply.get("type") != "REVIEW_RESULT" or not isinstance(revoke, list):
                # A reply that cannot be read is not a pass with nothing to
                # revoke. Treating it as one would make a broken Controller
                # indistinguishable from a healthy quiet one.
                raise RuntimeError(f"not a REVIEW_RESULT: {_short(reply)}")
        except RuntimeError as exc:
            return self._review_failed(live, str(exc))

        self._review_failures = 0

        revoked: list[str] = []
        seen: set[str] = set()
        for entry in revoke:
            if not isinstance(entry, dict):
                status(log, "Ignoring malformed revoke entry", entry=_short(entry))
                continue
            sid = entry.get("sid")
            if not isinstance(sid, str) or not sid:
                status(log, "Ignoring revoke entry that names no sid", entry=_short(entry))
                continue
            if sid in seen:
                continue  # revoke_sid already closed every session under it
            seen.add(sid)
            reason = str(entry.get("reason") or "no reason given")
            status(log, "REVOKING - the Controller withdrew this session",
                   session=str(entry.get("session_id", ""))[:8], sid=sid, reason=reason)
            revoked.extend(s.session_id for s in
                           TABLE.revoke_sid(sid, f"re-evaluation: {reason}"))

        if revoked:
            status(log, "Re-evaluation complete", checked=len(live), revoked=len(revoked))
        return revoked

    def _review_failed(self, live: list, error: str) -> list[str]:
        """One failed review pass: count it, say so loudly, and revoke
        everything once the streak reaches the tolerance.

        Loud on every single failure, because each one is a pass in which the
        Gateway kept enforcing grants nobody re-authorised. The tolerance
        exists so that a dropped packet does not become an outage, not so that
        a dead Controller can be ignored.
        """
        self._review_failures += 1
        remaining = self._failures_before_revoke - self._review_failures
        if remaining > 0:
            status(log, "SESSION REVIEW FAILED - live sessions NOT re-authorised",
                   failures=f"{self._review_failures}/{self._failures_before_revoke}",
                   sessions=len(live), revoking_after=f"{remaining} more",
                   url=self._url, error=error)
            return []

        status(log, "SESSION REVIEW FAILED - tolerance exhausted, REVOKING EVERY LIVE SESSION",
               failures=f"{self._review_failures}/{self._failures_before_revoke}",
               sessions=len(live), url=self._url, error=error)
        revoked: list[str] = []
        for sid in dict.fromkeys(s.sid for s in live):
            revoked.extend(s.session_id for s in
                           TABLE.revoke_sid(sid, "Controller unreachable"))
        # Reset: nothing unreviewed is standing any more, so by the measure
        # above the streak is over and the next session starts with its full
        # tolerance. This does not let a dead Controller be waited out. No
        # session can be opened at all while /spa_verify is failing, and one
        # opened in a lull still cannot outlive
        # GATEWAY_REVIEW_FAILURES_BEFORE_REVOKE failed passes - it is cut on
        # the same schedule, from its own start rather than from a streak it
        # was never part of.
        self._review_failures = 0
        return revoked
