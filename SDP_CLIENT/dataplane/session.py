"""The client's data path: one TLS request across the port the SPA knock
just opened.

Why this module exists. A knock that returns SPA_OK proves only that the
Gateway accepted a ticket and punched a pinhole. Nothing has crossed the
perimeter yet, and an open port is not access. This is the step that turns
an access *decision* into an access *fact*, and it is deliberately the
narrowest client possible: one connection, one GET, one response, then
closed.

Why the certificate check is non-negotiable. The Gateway works like a ZIA
PSE: it terminates this TLS session, inspects the cleartext, and re-forwards
the request to the resource over the internal-only data plane. It is
therefore a man in the middle *by design* — which is exactly why the client
must prove it is talking to *that* middle and not some other. The Gateway
presents a certificate issued by the project CA, and that CA file is the
only trust anchor loaded here: not the system store, not an exception list.
A Gateway that cannot prove itself gets no token. There is no unverified
fallback path in this module, and a missing CA file is a hard failure rather
than a quiet downgrade, because the downgrade is the attack this whole
architecture is built to refuse.

Standard library only (ssl, socket, http.client). The endpoint and the
timeout come from the caller, which already holds the settings object; this
module owns only the CA location, since that is the one value a transport
must not be talked out of.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import time
from dataclasses import dataclass

from shared.utils.logger import get_logger, status

log = get_logger("DataPlane")

# The project CA from `admin_cli.py init-ca`. Relative to SDP_CLIENT/, which
# mirrors the Gateway's own ./certs/pki/ layout so one issued bundle can be
# dropped into either component unchanged.
#
# This belongs in shared/config/settings.py's client block as
# `client_ca_cert_path`; it is read here directly only because this change
# does not own that file. Reading it at call time, not at import, keeps a
# late `load_dotenv()` from being shadowed by an import-time snapshot.
CA_CERT_PATH_DEFAULT = "./certs/pki/ca.crt"
CA_CERT_PATH_ENV = "CLIENT_CA_CERT_PATH"

# The one resource endpoint this phase knows about, and the header it is
# authorised with. Both are fixed by the project's HTTP contract.
RESOURCE_PATH = "/api/data"

# A protected resource answers in kilobytes. Anything past this is either a
# misconfigured upstream or someone feeding the client a response it should
# not be parsing, so the read stops rather than growing without bound.
_MAX_BODY_BYTES = 256 * 1024


class DataPlaneError(Exception):
    """The request did not complete. Carries why, so the caller can log a
    cause instead of a bare failure."""


class CaCertMissing(DataPlaneError):
    """No CA bundle to verify the Gateway against. Fatal on purpose: the only
    alternative is an unverified connection."""


class GatewayNotTrusted(DataPlaneError):
    """The Gateway's certificate did not verify against the project CA, or
    its name did not match. Either the wrong box answered or the pinhole is
    being intercepted by something that is not our Gateway."""


class GatewayUnreachable(DataPlaneError):
    """No TCP/TLS session could be established, or it died mid-request. The
    usual cause is a pinhole that has already closed, or the Gateway's proxy
    not yet listening."""


@dataclass(frozen=True)
class DataPlaneResult:
    """What came back: enough to log and to decide, nothing more."""

    status_code: int
    body: str
    elapsed_ms: float

    @property
    def ok(self) -> bool:
        return self.status_code == 200


def ca_cert_path() -> str:
    """Where the project CA is expected. Overridable per deployment, because
    a native client and a containerised one mount it in different places."""
    return os.environ.get(CA_CERT_PATH_ENV) or CA_CERT_PATH_DEFAULT


def build_tls_context(ca_path: str | None = None) -> ssl.SSLContext:
    """A context that trusts the project CA and nothing else.

    `create_default_context` with an explicit `cafile` loads *only* that
    file — it skips the system store entirely — which is the property this
    whole module rests on. Hostname checking and certificate requirement are
    asserted rather than assumed, so that a future edit loosening them has
    to delete a line that says what it is doing.
    """
    path = ca_path or ca_cert_path()
    if not os.path.isfile(path):
        raise CaCertMissing(
            f"Project CA not found at {os.path.abspath(path)}. Issue it with "
            f"`admin_cli.py init-ca` and point {CA_CERT_PATH_ENV} at ca.crt. "
            "Refusing to connect: an unverified data path is worse than none."
        )
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=path)
    except (ssl.SSLError, OSError) as exc:
        raise CaCertMissing(f"Project CA at {path} is not a usable PEM bundle: {exc}") from exc
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def fetch(access_token: str, host: str, port: int, *,
          path: str = RESOURCE_PATH,
          server_hostname: str | None = None,
          ca_path: str | None = None,
          timeout: float = 10.0) -> DataPlaneResult:
    """GET `path` from the Gateway's TLS proxy, bearing the IDP access token.

    `server_hostname` defaults to `host`: the Gateway's proxy certificate
    names sdp-gateway, localhost and 127.0.0.1, which covers both the compose
    network and a native run. It is separable only for the case where the
    knock had to be aimed at an address the certificate cannot name.

    Raises DataPlaneError (one of the three subclasses) rather than returning
    a sentinel, so a transport failure can never be mistaken for an HTTP
    status the resource actually sent.
    """
    context = build_tls_context(ca_path)
    sni = server_hostname or host
    started = time.monotonic()

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise GatewayUnreachable(
            f"cannot open {host}:{port} - is the SPA pinhole still open? ({exc})") from exc

    try:
        tls = context.wrap_socket(raw, server_hostname=sni)
    except ssl.SSLCertVerificationError as exc:
        raw.close()
        raise GatewayNotTrusted(
            f"{host}:{port} did not verify against {os.path.abspath(ca_path or ca_cert_path())} "
            f"(expected name {sni}): {exc.verify_message or exc}") from exc
    except ssl.SSLError as exc:
        raw.close()
        raise GatewayNotTrusted(f"TLS handshake with {host}:{port} failed: {exc}") from exc
    except OSError as exc:
        raw.close()
        raise GatewayUnreachable(f"TLS handshake with {host}:{port} failed: {exc}") from exc

    status(log, "Data path established", gateway=f"{host}:{port}", sni=sni,
           tls=tls.version(), cipher=(tls.cipher() or ("", "", 0))[0],
           peer_cn=_subject_cn(tls))

    # The socket is handed to http.client already wrapped, so the TLS leg is
    # built and verified here, in one place, instead of inside connect().
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    conn.sock = tls
    try:
        conn.request("GET", path, headers={
            "Host": sni,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Connection": "close",
        })
        response = conn.getresponse()
        body = response.read(_MAX_BODY_BYTES)
        code = response.status
    except (http.client.HTTPException, ssl.SSLError, OSError) as exc:
        raise GatewayUnreachable(f"{path} failed mid-request on {host}:{port}: {exc}") from exc
    finally:
        conn.close()

    return DataPlaneResult(
        status_code=code,
        body=body.decode("utf-8", errors="replace"),
        elapsed_ms=(time.monotonic() - started) * 1000.0,
    )


def _subject_cn(tls: ssl.SSLSocket) -> str | None:
    """The peer's CN, for the log line only. Verification already happened in
    the handshake; this is narration, never a decision."""
    try:
        peer = tls.getpeercert() or {}
    except ValueError:
        return None
    for rdn in peer.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None
