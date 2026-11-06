"""The Gateway's record of what is currently open.

Every grant made by segmentation.py is recorded here and closed again when
its lease runs out. One background reaper sweeps the whole table on a fixed
interval, rather than one `threading.Timer` per grant: a thread per open
session does not scale, and it leaves nothing to query. Having a table makes
three things possible that a bare timer cannot:

  * Revocation by session id or by IDP session id (sid) — what the Controller
    needs when a device's trust score collapses mid-session. A timer can only
    be waited out.
  * An operator view of what is reachable right now, and by whom.
  * Closing everything cleanly on shutdown, so a Gateway restart does not
    strand accept rules in the kernel.

A lease is a lease, not a grant: a client that stops re-authorising loses
reachability without anyone intervening.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from firewall import rules
from shared.utils.logger import get_logger, status

log = get_logger("Sessions")

REAP_INTERVAL_SECONDS = 1.0


@dataclass
class Session:
    session_id: str
    sid: str                      # the IDP session id the knock ticket carried
    client_ip: str
    access_port: int
    protocol: str
    acl: str                      # FULL | LIMITED
    hosts: tuple[str, ...]        # () = any destination (FULL)
    opened_at: float
    expires_at: float
    # The posture the IDP attested in the knock ticket that opened this
    # session. Kept so the Controller can re-score a live session without a
    # fresh knock: posture arrives signed inside a ticket and there is no
    # honest way to re-derive it between knocks, so the admission-time value
    # is carried forward rather than guessed at.
    posture_signals: dict[str, bool] = field(default_factory=dict)
    closed_reason: str | None = field(default=None)

    @property
    def remaining(self) -> float:
        return max(0.0, self.expires_at - time.time())

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class SessionTable:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None

    # -- grants ------------------------------------------------------------

    def open(self, *, session_id: str, sid: str, client_ip: str, access_port: int,
             protocol: str, ttl_seconds: float, acl: str = "FULL",
             hosts: tuple[str, ...] = (),
             posture_signals: dict[str, bool] | None = None) -> Session:
        """Insert the firewall rules for one grant and record it.

        `hosts` empty means the hole reaches any destination. One rule is
        inserted per host otherwise, which is how LIMITED is enforced.

        `posture_signals` is what the IDP attested in the knock ticket, kept
        so the Controller can re-score this session later.
        """
        now = time.time()
        targets: tuple[str | None, ...] = hosts or (None,)
        for host in targets:
            rules.allow(client_ip, access_port, protocol, dst_ip=host)

        session = Session(
            session_id=session_id, sid=sid, client_ip=client_ip,
            access_port=access_port, protocol=protocol, acl=acl, hosts=hosts,
            opened_at=now, expires_at=now + ttl_seconds,
            posture_signals=dict(posture_signals or {}),
        )
        with self._lock:
            self._sessions[session_id] = session

        status(log, "SESSION OPEN", session=session_id[:8], sid=sid, client_ip=client_ip,
               port=f"{protocol}/{access_port}", acl=acl,
               hosts=",".join(hosts) if hosts else "any", ttl=f"{ttl_seconds:g}s")
        return session

    def close(self, session_id: str, reason: str) -> Session | None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return None
        for host in (session.hosts or (None,)):
            rules.revoke(session.client_ip, session.access_port, session.protocol, dst_ip=host)
        session.closed_reason = reason
        status(log, "SESSION CLOSED", session=session_id[:8], sid=session.sid, reason=reason)
        return session

    def revoke_sid(self, sid: str, reason: str = "revoked by Controller") -> list[Session]:
        """Close every session belonging to one IDP session id.

        This is the entry point for the Controller's trust feedback: a score
        that falls below policy mid-session ends the session now, instead of
        waiting out its lease.
        """
        with self._lock:
            ids = [s.session_id for s in self._sessions.values() if s.sid == sid]
        closed = [c for sid_ in ids if (c := self.close(sid_, reason)) is not None]
        status(log, "Revoked by sid", sid=sid, sessions=len(closed), reason=reason)
        return closed

    # -- reaper ------------------------------------------------------------

    def start_reaper(self, interval: float = REAP_INTERVAL_SECONDS) -> None:
        if self._reaper is not None:
            return

        def loop() -> None:
            while not self._stop.wait(interval):
                with self._lock:
                    expired = [s.session_id for s in self._sessions.values() if s.expired]
                for session_id in expired:
                    self.close(session_id, "lease expired")

        self._reaper = threading.Thread(target=loop, daemon=True, name="session-reaper")
        self._reaper.start()
        status(log, "Lease reaper started", interval=f"{interval:g}s")

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            ids = list(self._sessions)
        for session_id in ids:
            self.close(session_id, "gateway shutdown")

    # -- views -------------------------------------------------------------

    def active(self) -> list[Session]:
        with self._lock:
            return sorted(self._sessions.values(), key=lambda s: s.opened_at)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


# One table per Gateway process. segmentation.py and any future admin
# endpoint act on this instance.
TABLE = SessionTable()
