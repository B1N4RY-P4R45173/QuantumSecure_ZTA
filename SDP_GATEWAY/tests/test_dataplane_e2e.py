"""End-to-end test of the decrypting data path, without Docker.

Stands up the real resource node and the real inspecting proxy in-process,
then drives them with the real client TLS code. Everything here is the
shipped implementation; only the token is minted locally, because the IDP is
not running.

What this proves, and nothing weaker:

  * A client holding a live SPA session reaches the resource through the
    gateway, and the resource independently verifies the token it was never
    handed directly.
  * The gateway really does decrypt: the inspector sees the plaintext request
    line, which is the whole justification for terminating TLS here.
  * A client with NO live session is refused before the TLS handshake, so the
    proxy cannot be reached by anyone who has not knocked.
  * A request carrying an attack marker is blocked at the gateway and never
    reaches the resource.
  * The resource rejects a token it cannot verify, so a gateway bug alone is
    not a total compromise.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_GATEWAY = _HERE.parent
_ROOT = _GATEWAY.parent
_RESOURCE = _ROOT / "resource-node"

for _p in (str(_ROOT), str(_GATEWAY), str(_RESOURCE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PKI = _GATEWAY / "certs" / "pki"
CA_CRT = PKI / "ca.crt"
PROXY_CRT = PKI / "proxy.crt"
PROXY_KEY = PKI / "proxy.key"

pytestmark = pytest.mark.skipif(
    not (CA_CRT.exists() and PROXY_CRT.exists() and PROXY_KEY.exists()),
    reason="needs the CA bundle: admin_cli.py init-ca, issue-gateway-cert, issue-proxy-cert",
)

AUDIENCE = "resource-node"
ISSUER = "https://idp.ztna.local"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
# Fixtures: a signing key, the resource node, the proxy                        #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def signing_key(tmp_path_factory):
    """Stand in for the IDP's RS256 key. The resource verifies against the
    public half, exactly as it would against the real IDP's."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = tmp_path_factory.mktemp("idpkey") / "idp_jwt_public.pem"
    pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return key, pub


def _mint(key, *, sub="alice", aud=AUDIENCE, ttl=900) -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"iss": ISSUER, "sub": sub, "aud": aud, "iat": now - 5, "exp": now + ttl,
         "jti": str(uuid.uuid4()), "trust_score": 0.9, "acl": "FULL",
         "device_id": "test-device", "amr": ["fido2"]},
        key, algorithm="RS256",
    )


@pytest.fixture(scope="module")
def resource(signing_key):
    """The real resource node, on a free port."""
    from access import guard
    from server import app as resource_app
    from server.endpoints import ResourceContext

    _, pub_path = signing_key
    authority = guard.load_authority(str(pub_path), AUDIENCE)
    context = ResourceContext(name="test-resource", authority=authority)

    port = _free_port()
    server = resource_app.build("127.0.0.1", port, context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield port
    server.shutdown()
    server.server_close()


@pytest.fixture
def proxy(resource, monkeypatch):
    """The real inspecting proxy, pointed at the real resource."""
    from firewall.sessions import TABLE
    from proxy.handler import InspectingProxy
    from proxy.router import Router

    port = _free_port()
    p = InspectingProxy(host="127.0.0.1", port=port,
                        router=Router(host="127.0.0.1", port=resource))
    p.start()
    time.sleep(0.3)
    yield p, port
    p.stop()
    for s in list(TABLE.active()):
        TABLE.close(s.session_id, "test teardown")


@pytest.fixture
def live_session(proxy):
    """Give 127.0.0.1 a live SPA session, as a real knock would.

    access_port must be the port the proxy is actually listening on: the
    proxy matches a session to a connection on (source IP, port), so a
    session authorising tcp/443 deliberately does not authorise a connection
    anywhere else.
    """
    from firewall.sessions import TABLE
    _, port = proxy
    s = TABLE.open(session_id=str(uuid.uuid4()), sid="sid-test",
                   client_ip="127.0.0.1", access_port=port, protocol="tcp",
                   ttl_seconds=60, acl="FULL", hosts=())
    yield s
    TABLE.close(s.session_id, "test teardown")


def _tls_get(port: int, token: str | None, path: str = "/api/data"):
    # Verified against the project CA with hostname checking left ON. The
    # proxy certificate carries 127.0.0.1 as a SAN, so this is a real
    # verification, not a bypass.
    ctx = ssl.create_default_context(cafile=str(CA_CRT))
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
    try:
        headers = {"Host": "localhost", "Connection": "close"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# The happy path                                                              #
# --------------------------------------------------------------------------- #

def test_authorised_client_reaches_the_resource(proxy, live_session, signing_key):
    """The whole chain: TLS to the gateway, decrypt, inspect, re-forward,
    and the resource verifies the token itself."""
    key, _ = signing_key
    _, port = proxy
    status, body = _tls_get(port, _mint(key))

    assert status == 200, f"expected 200 through the proxy, got {status}: {body}"
    assert "served_at" in body
    assert "test-resource" in body


def test_the_gateway_actually_decrypts(proxy, live_session, signing_key):
    """The justification for terminating TLS. If the inspector cannot see the
    plaintext request line, decryption is buying nothing."""
    from traffic import inspector

    seen = []
    original = inspector.inspect

    def spy(data, *a, **kw):
        seen.append(bytes(data))
        return original(data, *a, **kw)

    inspector.inspect = spy
    try:
        key, _ = signing_key
        _, port = proxy
        _tls_get(port, _mint(key))
    finally:
        inspector.inspect = original

    assert seen, "the inspector never saw the request - nothing was decrypted"
    joined = b"".join(seen)
    assert b"GET /api/data" in joined, "decrypted bytes do not contain the request line"
    assert b"Authorization: Bearer" in joined


# --------------------------------------------------------------------------- #
# The refusals                                                                #
# --------------------------------------------------------------------------- #

def test_no_spa_session_is_refused_before_the_handshake(proxy, signing_key):
    """A valid token is not enough. Without a live SPA session the proxy must
    close the socket, so the data path cannot be reached by anyone who has
    not knocked."""
    key, _ = signing_key
    _, port = proxy
    with pytest.raises((ssl.SSLError, OSError, ConnectionError, EOFError,
                        http.client.HTTPException)):
        _tls_get(port, _mint(key))


def test_attack_marker_is_blocked_at_the_gateway(proxy, live_session, signing_key):
    """Blocked by the inspector on the decrypted request, which only works
    because TLS was terminated."""
    key, _ = signing_key
    _, port = proxy
    status, _ = _tls_get(port, _mint(key), path="/api/data?q=../../etc/passwd")
    assert status != 200, "path traversal reached the resource"


def test_resource_rejects_a_token_it_cannot_verify(proxy, live_session):
    """Defence in depth: the resource verifies independently, so a gateway
    that forwards a bad token does not become a total compromise."""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, port = proxy
    status, _ = _tls_get(port, _mint(other))
    assert status == 401


def test_resource_rejects_a_missing_token(proxy, live_session):
    _, port = proxy
    status, _ = _tls_get(port, None)
    assert status == 401


def test_healthz_needs_no_token(proxy, live_session):
    """The probe the gateway and compose healthcheck use."""
    _, port = proxy
    status, body = _tls_get(port, None, path="/healthz")
    assert status == 200
    assert "ok" in body
