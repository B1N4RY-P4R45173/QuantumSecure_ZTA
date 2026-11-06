"""One audit line per request, written whatever the outcome.

Why a module and not a log call at each call site: this node is the last hop
in the data path and the only place where "a decrypted request actually
reached the protected resource" can be asserted. Everything upstream can say
a connection was permitted; only this can say it was served.

What the trail can and cannot establish is worth being blunt about, because
the Gateway in front of this node terminates TLS and re-forwards on a new
connection (the ZIA-PSE pattern). By the time bytes arrive here the client's
own address is gone: the peer is ALWAYS the Gateway. So ``peer`` is a
plumbing fact, useful for spotting a request that arrived from somewhere
other than the Gateway, and useless as an identity. The identity is ``sub``
and ``sid``, which come out of a token whose signature already verified —
those are the fields to correlate with the IDP's issuance log and the
Gateway's session table.

The denial lines are the ones that matter most, and a denial that produces no
line is the failure this module exists to prevent: the handler records before
it writes the response, so a client that disconnects mid-response still
leaves the decision on record. ``reason`` is operator-only and is never the
text sent to the client.
"""

from __future__ import annotations

from shared.utils.logger import get_logger, status

log = get_logger("Res-Audit")

ALLOW = "ALLOW"
DENY = "DENY"


def record(*, peer: str, method: str, path: str, decision: str, status_code: int,
           subject: str | None = None, sid: str | None = None, jti: str | None = None,
           reason: str | None = None, elapsed_ms: float | None = None) -> None:
    """Write the single line for one request.

    Fields are emitted in a fixed order, and absent ones are dropped rather
    than printed as ``None``, so the lines stay greppable: every served
    request has ``sub=``, every refusal has ``reason=``.
    """
    fields: dict[str, object] = {
        "peer": peer,
        "request": f"{method} {path}",
        "status": status_code,
    }
    if subject is not None:
        fields["sub"] = subject
    if sid is not None:
        fields["sid"] = sid
    if jti is not None:
        fields["jti"] = jti
    if reason is not None:
        fields["reason"] = reason
    if elapsed_ms is not None:
        fields["took"] = f"{elapsed_ms:.1f}ms"
    status(log, f"ACCESS {decision}", **fields)
