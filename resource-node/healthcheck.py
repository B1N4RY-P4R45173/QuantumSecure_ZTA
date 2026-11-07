"""The container's own /healthz probe.

A one-liner in the Dockerfile cannot do this any more, because the node now
listens two different ways and the probe has to match whichever is in use:

  * single host  - plain HTTP, because the resource is on an internal-only
    network with no route off it and the inner leg is cleartext by design;
  * split hosts  - HTTPS, and the listener DEMANDS a client certificate.

The old probe spoke plain HTTP unconditionally. Against the TLS listener it
got `ConnectionResetError: [Errno 104]` on every attempt, so a resource that
was serving the Gateway perfectly well reported `unhealthy` forever. That is
worse than no probe: it is a red light that means nothing, and the next real
failure hides behind it.

It presents health.crt rather than resource.crt. A TLS server rejects a
server certificate offered as a client one, and borrowing a Gateway's key
would put a Gateway identity on the resource host for no reason.

Exit 0 = healthy. Anything else = not.
"""
from __future__ import annotations

import http.client
import os
import ssl
import sys

PORT = int(os.environ.get("RESOURCE_PORT", "7443"))
HOST = "127.0.0.1"
TIMEOUT = 3
CERT_DIR = os.environ.get("RESOURCE_CERT_DIR", "certs/pki")


def tls_enabled() -> bool:
    return os.environ.get("RESOURCE_TLS", "").strip().lower() in ("1", "true", "yes")


def connect() -> http.client.HTTPConnection:
    if not tls_enabled():
        return http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(os.path.join(CERT_DIR, "ca.crt"))
    ctx.load_cert_chain(os.path.join(CERT_DIR, "health.crt"),
                        os.path.join(CERT_DIR, "health.key"))
    # Hostname verification stays ON. issue-resource-cert always includes
    # 127.0.0.1 in the SANs (RESOURCE_SAN_HOSTS), so the loopback address this
    # probe dials is covered and there is nothing to switch off. A probe that
    # disabled the check to make itself pass would stop testing the one thing
    # worth testing.
    return http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=TIMEOUT)


def main() -> int:
    conn = None
    try:
        conn = connect()
        conn.request("GET", "/healthz")
        return 0 if conn.getresponse().status == 200 else 1
    except Exception as exc:
        print(f"healthcheck failed (tls={tls_enabled()}): "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
