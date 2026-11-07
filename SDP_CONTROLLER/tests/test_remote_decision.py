"""The Controller decides the same way over mTLS as it does in-process.

That equivalence is the whole justification for extracting decision.py: two
copies of this judgement would drift, and the first symptom would be a
remote deployment quietly allowing something the local one refused.

These tests stand the real service up with real certificates and drive it
with the real Gateway client. Nothing on the path is mocked.

One bug these caught, worth keeping a test for: the service originally
validated `received_at` and then dropped it, so it scored against its own
processing clock. policies.yaml has a time-of-day rule, so the same knock
decided FULL in-process and LIMITED remotely whenever it crossed an hour
boundary. test_remote_and_in_process_agree_on_the_hour pins it.
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_CONTROLLER = _HERE.parent
_ROOT = _CONTROLLER.parent
for _p in (str(_ROOT), str(_CONTROLLER), str(_ROOT / "SDP_GATEWAY")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

PKI = _CONTROLLER / "certs" / "pki"
GW_PKI = _ROOT / "SDP_GATEWAY" / "certs" / "pki"

pytestmark = pytest.mark.skipif(
    not ((PKI / "controller.crt").exists() and (GW_PKI / "gateway.crt").exists()),
    reason="needs the CA bundle: admin_cli.py init-ca, issue-gateway-cert, issue-controller-cert",
)

HEALTHY = {k: True for k in ("device_managed", "os_patched", "known_device",
                             "location_expected", "disk_encrypted", "antivirus_running")}
WG_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

# Pinned so a test run at 03:00 does not see mfa-off-hours narrow the grant.
NOON = time.mktime(time.struct_time((2026, 11, 7, 12, 0, 0, 4, 311, -1)))
MIDNIGHT = time.mktime(time.struct_time((2026, 11, 7, 23, 30, 0, 4, 311, -1)))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def controller():
    """The real service, with the real certificates, on a free port."""
    from decision import PolicyEngine
    from service import app as svc

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(PKI / "controller.crt"), str(PKI / "controller.key"))
    ctx.load_verify_locations(str(PKI / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    port = _free_port()
    server = svc.build("127.0.0.1", port, PolicyEngine(), ctx)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    yield f"https://127.0.0.1:{port}", port
    server.shutdown()
    server.server_close()


@pytest.fixture
def remote(controller, monkeypatch):
    monkeypatch.chdir(_ROOT / "SDP_GATEWAY")   # the cert defaults are relative
    from controller.remote import RemoteController
    url, _ = controller
    return RemoteController(url)


def _knock(posture, *, sid="sid-test", port=443, at=NOON):
    return {"type": "SPA_VERIFY", "client_ip": "10.0.0.7", "access_port": port,
            "protocol": "tcp", "received_at": at,
            "identity": {"sid": sid, "ticket_id": "t-1",
                         "wg_public_key": WG_KEY, "posture": posture}}


# --------------------------------------------------------------------------- #
# The decision crosses the wire intact                                        #
# --------------------------------------------------------------------------- #

def test_a_healthy_device_is_approved_remotely(remote):
    reply = remote.send(_knock(HEALTHY))
    assert reply["type"] == "APPROVED"
    assert reply["acl"] == "FULL"
    assert reply["ttl_seconds"] > 0
    assert reply["session_id"]


def test_no_posture_is_denied_remotely(remote):
    reply = remote.send(_knock({}))
    assert reply["type"] == "DENIED"
    assert "19" in reply["reason"], f"expected the score in the reason: {reply['reason']}"


def test_remote_and_in_process_agree(remote):
    """The equivalence the extraction exists to guarantee."""
    from decision import PolicyEngine
    local = PolicyEngine()

    for label, posture in (("healthy", HEALTHY), ("none", {}),
                           ("client-reported", {"os_patched": True, "disk_encrypted": True,
                                                "antivirus_running": True}),
                           ("attested", {"device_managed": True, "known_device": True,
                                         "location_expected": True})):
        here = local.decide(client_ip="10.0.0.7", access_port=443, protocol="tcp",
                            sid="sid-test", posture=posture, received_at=NOON)
        there = remote.send(_knock(posture))
        approved_there = there["type"] == "APPROVED"
        assert here.approved == approved_there, (
            f"{label}: in-process approved={here.approved}, remote={approved_there}")
        if here.approved:
            assert here.acl == there["acl"], f"{label}: acl differs"


def test_remote_and_in_process_agree_on_the_hour(remote):
    """Regression: the service validated received_at and then dropped it, so
    it scored on its own clock and disagreed across an hour boundary."""
    from decision import PolicyEngine
    local = PolicyEngine()

    for at in (NOON, MIDNIGHT):
        here = local.decide(client_ip="10.0.0.7", access_port=443, protocol="tcp",
                            sid="sid-test", posture=HEALTHY, received_at=at)
        there = remote.send(_knock(HEALTHY, at=at))
        assert there["type"] == "APPROVED"
        assert here.acl == there["acl"], (
            f"at {time.strftime('%H:%M', time.localtime(at))} in-process said "
            f"{here.acl} and the Controller said {there['acl']}")


# --------------------------------------------------------------------------- #
# Revocation crosses the wire                                                 #
# --------------------------------------------------------------------------- #

def test_session_review_revokes_across_the_wire(remote):
    """Revocation has to travel Controller -> Gateway, but the Gateway dials
    out, so it asks rather than being told."""
    from firewall.sessions import TABLE

    for s in list(TABLE.active()):
        TABLE.close(s.session_id, "test setup")

    doomed = TABLE.open(session_id=str(uuid.uuid4()), sid="sid-doomed",
                        client_ip="10.0.0.7", access_port=443, protocol="tcp",
                        ttl_seconds=300, acl="FULL", hosts=(),
                        posture_signals={})          # no posture -> fails policy
    try:
        revoked = remote.reevaluate()
        assert doomed.session_id in revoked
        assert TABLE.active() == []
    finally:
        for s in list(TABLE.active()):
            TABLE.close(s.session_id, "test teardown")


# --------------------------------------------------------------------------- #
# Fail closed                                                                 #
# --------------------------------------------------------------------------- #

def test_an_unreachable_controller_denies(monkeypatch):
    """No decision is not an approval."""
    monkeypatch.chdir(_ROOT / "SDP_GATEWAY")
    from controller.remote import RemoteController

    dead = RemoteController(f"https://127.0.0.1:{_free_port()}")
    reply = dead.send(_knock(HEALTHY))
    assert reply["type"] == "DENIED"


def test_a_client_without_a_certificate_cannot_connect(controller):
    """mTLS is the point: an unsigned caller never reaches the decision."""
    _, port = controller
    ctx = ssl.create_default_context(cafile=str(PKI / "ca.crt"))
    with pytest.raises((ssl.SSLError, OSError, ConnectionError)):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                tls.recv(64)


def test_healthz_answers_a_certificated_caller(remote):
    assert remote.check_healthz()["status"] == "ok"
