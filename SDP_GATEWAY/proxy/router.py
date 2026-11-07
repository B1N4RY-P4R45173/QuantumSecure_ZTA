"""The inner leg: a new, plaintext HTTP connection to the resource.

Terminating TLS at the Gateway splits one client connection into two. This
module owns the second one, and it is a genuinely separate connection - not a
tunnel with the bytes shovelled through. That is the whole difference between
a pass-through and an inspecting proxy: the request that goes out is rebuilt
from the parse the inspector approved, so what was inspected and what was
forwarded cannot drift apart.

The inner leg is cleartext on purpose. data-plane-net is internal-only and
the resource has no route off it, so a second TLS session would buy nothing
but a second certificate to rotate - while costing the plaintext visibility
that justifies terminating in the first place. The trade is deliberate and
it is the reason that network must never be exposed.

Two refusals live here rather than in the handler, because both are about
the destination:

  ACL        A session's `hosts` is the micro-segmentation decision the
             Controller made. Empty means FULL - any destination behind the
             Gateway. Non-empty means only those, and this resource must be
             one of them or the connection is refused. The packet filter
             already pins the same thing at L3, so this is defence in depth
             on the path that bypasses it: the proxy's own socket to the
             resource is opened by the Gateway, not by the client, and
             nothing in the firewall chain constrains it.
  upstream   A resource that is down, slow or shouting must not become a
             hung client connection. Every socket here has a timeout and a
             byte cap, and a failure becomes a clean 502.

Hop-by-hop headers are dropped on the way through (RFC 7230 s6.1): they
describe the connection they arrived on, which has already ended at this
Gateway. End-to-end headers - Authorization above all - pass untouched,
because the resource validates that JWT offline and must see exactly what
the client signed up to send.
"""

from __future__ import annotations

import os
import socket
import ssl
from dataclasses import dataclass

from firewall.sessions import Session
from traffic.inspector import Verdict
from shared.utils.logger import get_logger, status

log = get_logger("Router")

# The resource behind the Gateway. RESOURCE_PORT is the contract's plain HTTP
# port; the host defaults to the compose service name on data-plane-net.
RESOURCE_HOST = os.environ.get("RESOURCE_HOST", "resource-node")
RESOURCE_PORT = int(os.environ.get("RESOURCE_PORT", "7443"))

CONNECT_TIMEOUT_SECONDS = 5.0
IO_TIMEOUT_SECONDS = 10.0
# A single JSON answer. A resource that wants to stream is a different design
# and would need a different relay; this cap keeps one bad upstream from
# filling the Gateway's memory.
MAX_RESPONSE_BYTES = 1 << 20

# Headers that describe the connection they arrived on and must not be
# re-forwarded onto a different one.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})

_REASONS = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            413: "Payload Too Large", 502: "Bad Gateway", 504: "Gateway Timeout"}


class DestinationRefused(PermissionError):
    """The session's ACL does not reach the resource this proxy fronts."""


class UpstreamUnavailable(RuntimeError):
    """The resource could not be reached, or did not answer sanely."""


@dataclass(frozen=True)
class Response:
    """What came back from the resource, kept byte-exact.

    The raw bytes are relayed verbatim rather than re-serialised: the client
    must receive the resource's own answer, down to its JSON, not the
    Gateway's idea of it.
    """

    status_code: int
    raw: bytes

    def __len__(self) -> int:
        return len(self.raw)


def error_response(status_code: int, message: str) -> bytes:
    """A Gateway-generated refusal, in the same JSON shape the resource uses.

    `message` names the rule or the condition, never anything the client
    sent. Echoing an attacker's own string back into a response body is how a
    blocked injection becomes a reflected one.
    """
    body = ('{"error":"' + message.replace('"', "'") + '"}').encode("utf-8")
    head = (
        f"HTTP/1.1 {status_code} {_REASONS.get(status_code, 'Error')}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + body


def _tls_context() -> ssl.SSLContext | None:
    """TLS for the inner leg, or None to keep it cleartext.

    None is correct on a single host: the resource is on an internal-only
    network with no route off it, so a second TLS session would buy nothing
    but a certificate to rotate, while costing the plaintext visibility that
    justifies terminating in the first place.

    RESOURCE_TLS=1 is for the deployment that breaks that assumption — a
    resource on ANOTHER MACHINE, where the inner leg crosses a real network
    carrying the client's bearer token. It is mutual: the Gateway verifies
    the resource's certificate against the project CA, and presents its own
    gateway.crt so the resource can refuse anything that is not a Gateway.

    A misconfiguration here fails closed. If the flag is set and the bundle
    is unusable the Gateway refuses to start, rather than quietly falling
    back to sending tokens across the network in the clear — which is the
    one outcome this flag exists to prevent.
    """
    if os.environ.get("RESOURCE_TLS", "").strip() not in ("1", "true", "yes"):
        return None

    ca = os.environ.get("GATEWAY_CA_CERT_PATH", "./certs/pki/ca.crt")
    cert = os.environ.get("GATEWAY_TLS_CERT_PATH", "./certs/pki/gateway.crt")
    key = os.environ.get("GATEWAY_TLS_KEY_PATH", "./certs/pki/gateway.key")
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
        ctx.load_cert_chain(cert, key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (FileNotFoundError, ssl.SSLError, OSError) as exc:
        raise SystemExit(
            f"RESOURCE_TLS is on but the certificate bundle is unusable "
            f"({exc}). Refusing to start: falling back to cleartext would "
            f"send bearer tokens across the network. Run "
            f"`admin_cli.py issue-resource-cert` and copy the bundle.") from exc

    status(log, "Inner leg: HTTPS to the resource (mutual TLS, project CA)",
           ca=ca, certificate=cert)
    return ctx


class Router:
    """Relays one inspected request to the resource and the answer back."""

    def __init__(self, host: str = RESOURCE_HOST, port: int = RESOURCE_PORT,
                 connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
                 io_timeout: float = IO_TIMEOUT_SECONDS,
                 max_response_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self._host = host
        self._port = port
        self._connect_timeout = connect_timeout
        self._io_timeout = io_timeout
        self._max_response_bytes = max_response_bytes
        self._tls = _tls_context()

    @property
    def destination(self) -> str:
        return f"{self._host}:{self._port}"

    # -- ACL ---------------------------------------------------------------- #

    def check_acl(self, session: Session) -> None:
        """Raise DestinationRefused unless the session may reach this resource.

        An empty `hosts` is FULL access by the session table's own definition,
        so it passes. A non-empty one is matched against the resource's name
        *and* its addresses: the Controller names hosts however it knows them,
        and a grant written as an IP must not be defeated by the proxy dialling
        a DNS name for the same machine.
        """
        if not session.hosts:
            return
        reachable = self._names()
        if reachable.isdisjoint(session.hosts):
            raise DestinationRefused(
                f"acl={session.acl} allows {','.join(session.hosts)}, "
                f"not {self.destination}")

    def _names(self) -> set[str]:
        """Every name this resource answers to: the configured one plus its
        resolved addresses. Resolution failure is not fatal - the name itself
        may be what the Controller named - so it falls back to the name."""
        names = {self._host}
        try:
            for info in socket.getaddrinfo(self._host, self._port, type=socket.SOCK_STREAM):
                names.add(info[4][0])
        except OSError as exc:
            status(log, "Could not resolve the resource - matching ACL by name only",
                   host=self._host, error=str(exc))
        return names

    # -- relay -------------------------------------------------------------- #

    def forward(self, verdict: Verdict, body: bytes = b"") -> Response:
        """Rebuild the approved request, send it in the clear, return the answer."""
        request = self._build_request(verdict, body)
        raw = self._exchange(request)
        return Response(status_code=_status_code(raw), raw=raw)

    def _build_request(self, verdict: Verdict, body: bytes) -> bytes:
        """Serialise the inspected parse onto the inner leg.

        Host is rewritten to the resource's authority because this is a new
        connection to a different origin, and Connection: close is forced so
        the response ends at EOF - which is what lets the relay below read a
        complete answer without implementing an HTTP body parser.
        """
        lines = [f"{verdict.method} {verdict.target} HTTP/1.1",
                 f"Host: {self.destination}"]
        for name, value in verdict.headers:
            lowered = name.lower()
            if lowered == "host" or lowered in _HOP_BY_HOP:
                continue
            lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        return head + body

    def _exchange(self, request: bytes) -> bytes:
        sock = None
        try:
            sock = socket.create_connection((self._host, self._port),
                                            timeout=self._connect_timeout)
            if self._tls is not None:
                # Only when the resource is on another machine. See _tls_context.
                sock = self._tls.wrap_socket(sock, server_hostname=self._host)
            sock.settimeout(self._io_timeout)
            sock.sendall(request)
            # Nothing more will be sent, so half-close: a resource that waits
            # for more of a request it already has would stall the exchange.
            #
            # NOT over TLS, and this is not a style choice. CPython's
            # ssl.SSLSocket.shutdown() sets self._sslobj = None before
            # delegating to the plain socket, so every recv() afterwards
            # bypasses decryption and hands back raw ciphertext. The symptom
            # is a relay that "works" and returns bytes which are not HTTP;
            # test_the_inner_leg_works_over_mutual_tls caught exactly that.
            #
            # Dropping it costs nothing here. The request carries
            # `Connection: close`, so the resource answers and closes without
            # needing to see a FIN first, and the read below still ends at
            # EOF.
            if self._tls is None:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass  # some stacks refuse a half-close; the read still works
            return self._read_response(sock)
        except socket.timeout as exc:
            raise UpstreamUnavailable(f"{self.destination} timed out") from exc
        except OSError as exc:
            raise UpstreamUnavailable(f"{self.destination} unreachable: {exc}") from exc
        finally:
            if sock is not None:
                sock.close()

    def _read_response(self, sock: socket.socket) -> bytes:
        """Read until EOF, which Connection: close guarantees is the whole
        response. A truncated relay would be worse than a failed one, so the
        cap raises instead of returning what it has."""
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > self._max_response_bytes:
                raise UpstreamUnavailable(
                    f"{self.destination} sent more than {self._max_response_bytes}B")
            chunks.append(chunk)
        if not chunks:
            raise UpstreamUnavailable(f"{self.destination} closed without answering")
        return b"".join(chunks)


def _status_code(raw: bytes) -> int:
    """The status line's code, or 0 when the answer is not recognisable HTTP.

    0 rather than an exception: the bytes are still relayed, and a status the
    Gateway could not read is a fact for the audit log, not a reason to drop
    the resource's answer on the floor.
    """
    status_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split(" ")
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0
