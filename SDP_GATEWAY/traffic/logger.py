"""One audit line per proxied connection, whatever became of it.

The point of a terminating proxy is that it is the only place in the system
where a client's traffic exists in the clear, so it is the only place that
can say what was actually asked for. That makes this record the evidentiary
part of the design: without it, "the Gateway inspects traffic" is a claim
with nothing behind it.

Two properties the record is built around:

  Exactly one line per connection, including the ones that went nowhere.
  A proxy that logs only what it served hides precisely the interesting
  traffic - the refusals. `record()` is a context manager and emits from a
  `finally`, so a refused source IP, a failed handshake and an unhandled
  exception all leave the same shaped line as a success.

  Nothing an attacker wrote reaches the log unescaped. The request target is
  theirs to choose; a CR or an ANSI escape in it would forge or hide log
  lines. Everything off the wire goes through `_safe()`.

The record is deliberately flat key=value through the shared `status()`
helper rather than JSON, so it reads the same as every other line this
project prints while still being greppable per field.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field
from typing import Iterator

from shared.utils.logger import get_logger, status

log = get_logger("Audit")

# What happened to the connection. Named so a log can be filtered on it.
OUTCOME_SERVED = "served"        # the resource answered and the client got it
OUTCOME_REFUSED = "refused"      # the Gateway said no: no session, verdict, ACL
OUTCOME_FAILED = "failed"        # something broke: handshake, upstream, us
OUTCOME_INCOMPLETE = "incomplete"  # the default, and the honest one until set

# A request target is attacker-chosen and can be as long as the inspector's
# cap allows. Truncate it in the log: evidence, not a transcript.
_TARGET_LIMIT = 160


def _safe(value: object, limit: int = _TARGET_LIMIT) -> str:
    """Make any wire-derived value safe to print on one line.

    unicode_escape turns CR, LF and ESC into visible escapes, which is what
    stops a crafted path from injecting or overwriting log lines.
    """
    text = str(value)
    clipped = text[:limit] + ("..." if len(text) > limit else "")
    return clipped.encode("unicode_escape").decode("ascii")


@dataclass
class ConnectionRecord:
    """Everything worth knowing about one connection through the proxy."""

    peer_ip: str
    peer_port: int = 0
    started_at: float = field(default_factory=time.monotonic)
    session_id: str = "-"
    sid: str = "-"
    method: str = "-"
    target: str = "-"
    verdict: str = "-"
    findings: tuple[str, ...] = ()
    bytes_in: int = 0
    bytes_out: int = 0
    upstream_status: int | None = None
    outcome: str = OUTCOME_INCOMPLETE
    reason: str = ""

    # -- mutators, in the order a connection meets them -------------------- #

    def bind(self, session) -> None:
        """Note which live session let this connection past the door."""
        self.session_id = session.session_id
        self.sid = session.sid

    def saw(self, verdict) -> None:
        """Record the inspector's parse and decision."""
        self.method = verdict.method or "-"
        self.target = verdict.target or "-"
        self.verdict = "allow" if verdict.allowed else "block"
        self.findings = verdict.rules

    def served(self, status_code: int) -> None:
        self.upstream_status = status_code
        self.outcome = OUTCOME_SERVED

    def refuse(self, reason: str) -> None:
        self.outcome = OUTCOME_REFUSED
        self.reason = reason

    def failed(self, error: BaseException | str) -> None:
        self.outcome = OUTCOME_FAILED
        self.reason = (f"{type(error).__name__}: {error}"
                       if isinstance(error, BaseException) else str(error))

    # -- views -------------------------------------------------------------- #

    @property
    def duration_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000.0

    @property
    def peer(self) -> str:
        return f"{self.peer_ip}:{self.peer_port}"

    @property
    def request(self) -> str:
        """The request line as inspected, or "-" when it never got that far."""
        if self.method == "-" and self.target == "-":
            return "-"
        return f"{_safe(self.method, 16)} {_safe(self.target)}"

    def emit(self) -> None:
        """Print the one line. Called from a finally - must never raise."""
        status(
            log, "PROXY CONN",
            peer=self.peer,
            session=self.session_id[:8],
            sid=_safe(self.sid, 64),
            request=self.request,
            verdict=self.verdict,
            findings=",".join(self.findings) or "-",
            status=self.upstream_status if self.upstream_status is not None else "-",
            bytes_in=self.bytes_in,
            bytes_out=self.bytes_out,
            outcome=self.outcome,
            reason=_safe(self.reason) or "-",
            duration=f"{self.duration_ms:.1f}ms",
        )


@contextlib.contextmanager
def record(peer: tuple[str, int]) -> Iterator[ConnectionRecord]:
    """Open an audit record for one connection and guarantee it is emitted.

    An exception on the way through is attributed to the connection and
    re-raised rather than swallowed: the caller decides what to do about a
    broken connection, but the audit trail does not depend on the caller
    remembering to log it.
    """
    entry = ConnectionRecord(peer_ip=peer[0], peer_port=peer[1] if len(peer) > 1 else 0)
    try:
        yield entry
    except BaseException as exc:
        if entry.outcome in (OUTCOME_INCOMPLETE, OUTCOME_SERVED):
            entry.failed(exc)
        raise
    finally:
        entry.emit()
