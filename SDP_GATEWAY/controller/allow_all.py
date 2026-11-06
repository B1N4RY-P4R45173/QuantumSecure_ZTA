"""In-process stand-in for the SDP Controller: approves every verified knock.

No Policy Engine, no Policy Administrator. Every SPA_VERIFY that reaches it
has already passed the Gateway's own checks, and it approves all of them,
allocating a session for each. It exists so the Gateway can be built and run
end to end now; the real SDP Controller replaces it behind
controller.client.ControllerClient.

It answers with the same `acl` / `allowed_hosts` fields the real Controller
will, so the Gateway's segmentation path is exercised rather than bypassed.
The default is FULL, because a stand-in that silently narrowed access would
disguise the fact that no policy is being applied at all. Set
GATEWAY_STUB_ACL=LIMITED with GATEWAY_STUB_HOSTS=10.0.0.5,10.0.0.6 to
exercise micro-segmentation before a real Controller exists.
"""

from __future__ import annotations

import os
import threading
import time
import uuid

from shared.utils.logger import get_logger, status

log = get_logger("Controller")

DEFAULT_TTL_SECONDS = 30

# Stand-in policy, overridable from the environment so the LIMITED path can be
# exercised before a real Controller exists.
STUB_ACL = os.environ.get("GATEWAY_STUB_ACL", "FULL").upper()
STUB_HOSTS = tuple(h for h in os.environ.get("GATEWAY_STUB_HOSTS", "").split(",") if h)


class AllowAllController:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def send(self, msg: dict) -> dict:
        if msg.get("type") != "SPA_VERIFY":
            return {"type": "ERROR", "reason": f"unknown: {msg.get('type')}"}

        session_id = str(uuid.uuid4())
        with self._lock:
            now = time.time()
            self._sessions = {sid: s for sid, s in self._sessions.items() if s["expires_at"] > now}
            self._sessions[session_id] = {
                "client_ip": msg["client_ip"],
                "access_port": msg["access_port"],
                "protocol": msg["protocol"],
                "identity": msg["identity"],
                "acl": STUB_ACL,
                "allowed_hosts": STUB_HOSTS,
                "expires_at": now + self._ttl_seconds,
            }

        status(log, "APPROVED (allow-all)", session=session_id, client_ip=msg["client_ip"],
               sid=msg["identity"].get("sid"), port=msg["access_port"],
               acl=STUB_ACL, hosts=",".join(STUB_HOSTS) or "any", ttl=self._ttl_seconds)
        return {
            "type": "APPROVED",
            "session_id": session_id,
            "access_port": msg["access_port"],
            "protocol": msg["protocol"],
            "ttl_seconds": self._ttl_seconds,
            "acl": STUB_ACL,
            "allowed_hosts": list(STUB_HOSTS),
        }
