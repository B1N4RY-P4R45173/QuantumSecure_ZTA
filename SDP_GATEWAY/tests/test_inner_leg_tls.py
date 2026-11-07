"""The inner leg, when the resource is on another machine.

On a single host the Gateway talks to the resource in cleartext on purpose:
the resource sits on an internal-only network with no route off it, so a
second TLS session would buy nothing but a certificate to rotate.

Split across machines that justification is simply false. The inner leg then
crosses a real network carrying the client's BEARER TOKEN, and the port is
reachable by anything that can route to it. RESOURCE_TLS=1 turns that leg
into mutual TLS, and these tests pin the three properties that make it worth
having:

  * it is encrypted and it works end to end;
  * the resource REFUSES a caller with no client certificate, so reaching
    the port is worth nothing on its own;
  * a misconfigured Gateway fails to start rather than silently falling back
    to cleartext, which is the one outcome the flag exists to prevent.
"""

from __future__ import annotations

import importlib
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_GATEWAY = _HERE.parent
_ROOT = _GATEWAY.parent
for _p in (str(_ROOT), str(_GATEWAY), str(_ROOT / "resource-node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

RES_PKI = _ROOT / "IDENTITY_PROVIDER" / "certs" / "pki" / "resource"
GW_PKI = _GATEWAY / "certs" / "pki"

pytestmark = pytest.mark.skipif(
    not ((RES_PKI / "resource.crt").exists() and (GW_PKI / "gateway.crt").exists()),
    reason="needs admin_cli.py issue-resource-cert and issue-gateway-cert",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def tls_resource():
    """The real resource node, served over mutual TLS on a free port."""
    from server import app as resource_app
    from server.endpoints import ResourceContext
    from access import guard

    key = _ROOT / "IDENTITY_PROVIDER" / "certs" / "idp_jwt_public.pem"
    if not key.exists():
        pytest.skip("no IDP public key to verify tokens with")

    context = ResourceContext(
        name="resource-node",
        authority=guard.load_authority(str(key), "resource-node"))

    ctx = resource_app.tls_context(str(RES_PKI / "resource.crt"),
                                   str(RES_PKI / "resource.key"),
                                   str(RES_PKI / "ca.crt"))
    port = _free_port()
    server = resource_app.build("127.0.0.1", port, context, ctx)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield port
    server.shutdown()
    server.server_close()


def _router(monkeypatch, port: int):
    """A Router configured the way the cross-machine compose configures it."""
    monkeypatch.chdir(_GATEWAY)          # the cert paths are relative to it
    monkeypatch.setenv("RESOURCE_TLS", "1")
    from proxy import router as router_mod
    importlib.reload(router_mod)
    return router_mod, router_mod.Router(host="127.0.0.1", port=port)


# --------------------------------------------------------------------------- #

def test_the_inner_leg_works_over_mutual_tls(tls_resource, monkeypatch):
    """The whole point: it still relays, and now it is encrypted."""
    _mod, router = _router(monkeypatch, tls_resource)

    raw = router._exchange(
        b"GET /healthz HTTP/1.1\r\nHost: resource-node\r\n"
        b"Connection: close\r\n\r\n")

    assert raw, "no response over the TLS inner leg"
    assert b"200" in raw.split(b"\r\n", 1)[0], raw[:120]


def test_the_resource_refuses_a_caller_without_a_certificate(tls_resource):
    """Reaching the port must be worth nothing on its own.

    This is what replaces the internal-only network. Without it, moving the
    resource onto the LAN would expose it to anything that can route there.
    """
    ctx = ssl.create_default_context(cafile=str(RES_PKI / "ca.crt"))
    with pytest.raises((ssl.SSLError, OSError, ConnectionError)):
        with socket.create_connection(("127.0.0.1", tls_resource), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                tls.recv(64)


def test_a_cleartext_caller_gets_nothing_useful(tls_resource):
    """A plain HTTP request to a TLS port must not be served."""
    with socket.create_connection(("127.0.0.1", tls_resource), timeout=5) as raw:
        raw.settimeout(5)
        raw.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        try:
            got = raw.recv(64)
        except (ConnectionResetError, socket.timeout):
            got = b""
    assert b"200" not in got, "the resource answered an unencrypted request"


def test_a_broken_bundle_refuses_to_start_rather_than_fall_back(monkeypatch, tmp_path):
    """Fail closed.

    Falling back to cleartext because a certificate was missing would send
    bearer tokens across the network, which is exactly what this flag exists
    to prevent. It has to be louder than a warning.
    """
    monkeypatch.chdir(tmp_path)          # no certs here at all
    monkeypatch.setenv("RESOURCE_TLS", "1")
    monkeypatch.setenv("GATEWAY_CA_CERT_PATH", str(tmp_path / "absent-ca.crt"))

    from proxy import router as router_mod
    importlib.reload(router_mod)
    # The context is built when a Router is constructed, not at import, so
    # that is where the refusal has to happen.
    with pytest.raises(SystemExit) as caught:
        router_mod.Router(host="127.0.0.1", port=1)
    assert "cleartext" in str(caught.value).lower()


def test_without_the_flag_the_inner_leg_stays_cleartext(monkeypatch):
    """The single-host default must be untouched by any of this."""
    monkeypatch.delenv("RESOURCE_TLS", raising=False)
    from proxy import router as router_mod
    importlib.reload(router_mod)
    assert router_mod._tls_context() is None
