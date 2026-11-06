"""The client-facing leg: a TLS listener that terminates, inspects, forwards.

This is the ZIA PSE pattern applied to an SDP Gateway. The client opens TLS
to the Gateway believing it is the resource; the Gateway holds a certificate
the client's CA signed for that name, decrypts, inspects the plaintext, and
then opens its own plain HTTP connection inward (proxy/router.py). It is a
deliberate man-in-the-middle, and the only thing that makes it defensible is
that it is *ours*: the CA is the project's, the client was told to trust it,
and the decryption is paid for by the inspection in traffic/inspector.py.

Guard order is the point of this module, and it follows spa/listener.py:
cheapest, most decisive check first.

  1. A live session for the source IP.  Before the handshake.
  2. TLS handshake with the proxy certificate.
  3. Read the head, under a byte cap and a clock.
  4. Inspect the plaintext; a blocked verdict never reaches the resource.
  5. The session's ACL must reach the resource.
  6. Relay, and relay the answer back.

Step 1 happens before step 2 for a reason. A TLS handshake is the expensive
part of a connection, and an unauthorised source IP must not be able to make
the Gateway do asymmetric crypto, nor learn from a certificate that something
is listening here at all. A connection from an IP with no live session is
closed with no bytes written - the same silence the SPA listener answers a
bad knock with. The packet filter should already have dropped that packet;
this check is what holds when it is in dry-run, when the Gateway is reached
on a path the chain does not cover, or when a lease expires while the kernel
rule is still in place.

One request per connection, then close. Keep-alive would need a full HTTP/1.1
state machine on both legs to stay safe against smuggling, and the contract
here is a single GET. ALPN is pinned to http/1.1 so a client offering h2 is
told plainly rather than silently mis-framed.

Concurrency: one thread per connection, capped. Threads are right for this
shape of work (a handful of long-ish, IO-bound relays), the cap is what stops
a flood turning into thread exhaustion, and every connection is wrapped so
that no single bad one can take down the accept loop.
"""

from __future__ import annotations

import os
import socket
import ssl
import threading
import time
from pathlib import Path

from firewall.sessions import TABLE, Session
from proxy.router import DestinationRefused, Router, UpstreamUnavailable, error_response
from traffic import inspector
from traffic import logger as audit
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Proxy")

# The certificate the Gateway PRESENTS to clients - not gateway.crt, which is
# this Gateway's client identity on the mTLS link to the IDP. Issued by the
# project CA as a server certificate with SANs covering every name a client
# may dial.
PROXY_CERT_PATH = os.environ.get("GATEWAY_PROXY_CERT_PATH", "./certs/pki/proxy.crt")
PROXY_KEY_PATH = os.environ.get("GATEWAY_PROXY_KEY_PATH", "./certs/pki/proxy.key")

LISTEN_BACKLOG = 64
# Concurrent connections. Past this, new ones are closed immediately: a
# refusal an operator can see in the log beats unbounded thread growth.
MAX_CONNECTIONS = 64
# Whole-connection budget, handshake included. Generous for one GET, short
# enough that a slowloris holds a thread for seconds rather than for ever.
CONNECTION_TIMEOUT_SECONDS = 20.0
# How long stop() waits for the accept loop to notice.
SHUTDOWN_JOIN_SECONDS = 5.0


class ProxyNotConfigured(RuntimeError):
    """No usable proxy certificate, so there is nothing to terminate TLS with."""


def proxy_context(cert_path: str = PROXY_CERT_PATH,
                  key_path: str = PROXY_KEY_PATH) -> ssl.SSLContext:
    """The TLS context the Gateway presents to clients.

    Deliberately not shared.ca.cert_utils.server_context(): that one is the
    IDP's side of the Gateway link and sets CERT_REQUIRED, because there a
    peer without a certificate has no identity. Here the client has already
    proved who it is twice over - FIDO2/TPM to the IDP, then an ML-KEM SPA
    knock carrying the IDP's ticket to this Gateway - and the session table
    is what carries that proof into the data path. Demanding a client
    certificate as well would mean issuing one per device for an identity the
    Gateway already has, so this side asks for none and binds the connection
    to its session instead.
    """
    missing = [f"{what} ({path})" for what, path in
               (("proxy certificate", cert_path), ("proxy private key", key_path))
               if not Path(path).exists()]
    if missing:
        raise ProxyNotConfigured(
            "Gateway proxy certificate missing: " + ", ".join(missing)
            + " - issue it from the project CA as a SERVER certificate whose SANs"
              " cover sdp-gateway, localhost and 127.0.0.1, and place it beside"
              " gateway.crt in certs/pki/")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Same floor as the IDP link. Nothing on this data path predates TLS 1.3.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.verify_mode = ssl.CERT_NONE
    # One request per connection over HTTP/1.1; say so rather than letting a
    # client negotiate h2 and then be mis-framed.
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


class InspectingProxy:
    """Threaded TLS front end for one resource behind the Gateway."""

    def __init__(self, *, host: str | None = None, port: int | None = None,
                 context: ssl.SSLContext | None = None,
                 router: Router | None = None,
                 max_connections: int = MAX_CONNECTIONS,
                 connection_timeout: float = CONNECTION_TIMEOUT_SECONDS) -> None:
        self._host = host if host is not None else settings.gateway_host
        self._port = port if port is not None else settings.client_access_port
        self._context = context if context is not None else proxy_context()
        self._router = router if router is not None else Router()
        self._timeout = connection_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._max_connections = max_connections
        self._listener: socket.socket | None = None
        self._acceptor: threading.Thread | None = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> None:
        """Bind, then accept in a background thread.

        Binding happens on the caller's thread on purpose: a port already in
        use must fail startup where main.py can see it, not in a daemon thread
        whose exception nobody reads.
        """
        if self._acceptor is not None:
            return
        self._bind()
        self._acceptor = threading.Thread(target=self._accept_loop, daemon=True,
                                          name="proxy-accept")
        self._acceptor.start()

    def serve_forever(self) -> None:
        """Bind and accept on the calling thread, for a caller that blocks."""
        self._bind()
        self._accept_loop()

    def stop(self) -> None:
        """Stop accepting and release the port.

        Connections already in flight are left to finish or to hit their
        timeout; they hold no firewall state, and killing a relay mid-response
        would corrupt the client's answer for no gain. The listening socket is
        closed first, which is what wakes accept().
        """
        self._stop.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # never bound, or already gone
            listener.close()
        acceptor, self._acceptor = self._acceptor, None
        if acceptor is not None and acceptor.is_alive():
            acceptor.join(SHUTDOWN_JOIN_SECONDS)
        status(log, "Proxy stopped", port=self._port)

    @property
    def address(self) -> tuple[str, int]:
        """The bound address. After start() with port 0, the real port."""
        if self._listener is None:
            return self._host, self._port
        return self._listener.getsockname()[:2]

    def _bind(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self._host, self._port))
            listener.listen(LISTEN_BACKLOG)
        except OSError:
            listener.close()
            raise
        self._listener = listener
        # Port 0 in a test becomes a real port here; everything downstream
        # (the session's access_port must match) reads it back from the socket.
        self._port = listener.getsockname()[1]
        status(log, "TLS proxy bound", host=self._host, port=self._port,
               resource=self._router.destination, max_connections=self._max_connections)

    # -- accept loop -------------------------------------------------------- #

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:
            raise RuntimeError("the proxy was not bound - call start() or serve_forever()")

        while not self._stop.is_set():
            try:
                raw, addr = listener.accept()
            except OSError as exc:
                if self._stop.is_set():
                    break
                # A transient accept error (fd pressure, a peer that vanished)
                # must not end the loop; the small sleep stops a hard spin.
                status(log, "Accept failed", error=str(exc))
                time.sleep(0.05)
                continue

            if not self._slots.acquire(blocking=False):
                status(log, "PROXY REFUSED - too many connections in flight",
                       peer=addr[0], limit=self._max_connections)
                _close(raw)
                continue

            raw.settimeout(self._timeout)
            threading.Thread(target=self._serve, args=(raw, addr), daemon=True,
                             name=f"proxy-{addr[0]}:{addr[1]}").start()

    def _serve(self, raw: socket.socket, addr: tuple[str, int]) -> None:
        """One connection, start to finish. Never raises, never leaks the fd."""
        tls: ssl.SSLSocket | None = None
        try:
            with audit.record(addr) as entry:
                tls = self._handle(raw, addr, entry)
        except Exception as exc:
            # The audit record already carries the failure; this line is for
            # the operator watching the Gateway, not for the trail.
            status(log, "Connection failed", peer=addr[0],
                   error=f"{type(exc).__name__}: {exc}")
        finally:
            # Both, in this order: closing the TLS wrapper closes the fd, but
            # if the handshake never happened there is no wrapper to close.
            # Closed rather than unwrapped: unwrap() waits for the peer's
            # close_notify, which would let a client hold a thread and a slot
            # for the whole connection timeout. Every response this proxy
            # writes carries a Content-Length, so no client has to rely on
            # EOF framing to know it got the whole thing.
            _close(tls)
            _close(raw)
            self._slots.release()

    # -- one connection ------------------------------------------------------ #

    def _handle(self, raw: socket.socket, addr: tuple[str, int],
                entry: audit.ConnectionRecord) -> ssl.SSLSocket | None:
        """Run the guard order. Returns the TLS socket so _serve can close it."""
        peer_ip = addr[0]

        session = self._live_session(peer_ip)
        if session is None:
            # No handshake, no certificate, no bytes. An unauthorised source
            # learns nothing about what is behind this port.
            entry.refuse("no live session for the source IP")
            status(log, "PROXY REFUSED - no live session", peer=peer_ip, port=self._port)
            return None
        entry.bind(session)

        try:
            tls = self._context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            entry.refuse(f"TLS handshake failed: {exc}")
            status(log, "PROXY REFUSED - TLS handshake failed", peer=peer_ip,
                   session=session.session_id[:8], error=str(exc))
            return None

        head, pipelined = _read_head(tls)
        entry.bytes_in += len(head) + len(pipelined)

        verdict = inspector.inspect(head)
        entry.saw(verdict)
        if not verdict.allowed:
            status(log, "PROXY BLOCKED - inspection", peer=peer_ip,
                   session=session.session_id[:8], sid=session.sid,
                   rules=",".join(verdict.rules), detail=verdict.reason)
            entry.refuse(f"blocked: {','.join(verdict.rules)}")
            # Rule names only. The matched text is the client's own and goes
            # to the audit log, never back down the wire.
            entry.bytes_out += _send(tls, error_response(
                403, "blocked by gateway inspection: " + ",".join(verdict.rules)))
            return tls

        body = _read_body(tls, verdict.content_length, pipelined)
        entry.bytes_in += max(0, len(body) - len(pipelined))

        # Re-check the lease here, not just at accept. Everything above this
        # line can block: the handshake, then _read_head waiting for a client
        # that may take its time, then _read_body. A client that connects,
        # lets its lease run out, and only then sends its request would
        # otherwise be served against a session that no longer exists -
        # measured, before this check existed, as a 200 returned with the
        # session table empty.
        #
        # This is also what makes revocation bite. The Controller shares this
        # process and can call TABLE.revoke_sid() at any moment; without a
        # re-check, a revoked session would keep being served until the
        # client chose to disconnect. Authorisation is a lease, so it has to
        # be re-read at the point it is spent.
        session = self._live_session(peer_ip)
        if session is None:
            entry.refuse("lease expired or revoked before forwarding")
            status(log, "PROXY REFUSED - lease gone before forward", peer=peer_ip,
                   port=self._port)
            entry.bytes_out += _send(tls, error_response(
                403, "session expired or revoked"))
            return tls
        entry.bind(session)

        try:
            self._router.check_acl(session)
        except DestinationRefused as exc:
            status(log, "PROXY REFUSED - ACL", peer=peer_ip,
                   session=session.session_id[:8], acl=session.acl,
                   hosts=",".join(session.hosts) or "any", error=str(exc))
            entry.refuse(f"acl: {exc}")
            entry.bytes_out += _send(tls, error_response(
                403, "destination not permitted for this session"))
            return tls

        status(log, "PROXY FORWARD", peer=peer_ip, session=session.session_id[:8],
               sid=session.sid, request=f"{verdict.method} {verdict.target}",
               resource=self._router.destination, remaining=f"{session.remaining:.1f}s")

        try:
            response = self._router.forward(verdict, body)
        except UpstreamUnavailable as exc:
            status(log, "PROXY FAILED - resource unreachable", peer=peer_ip,
                   session=session.session_id[:8], error=str(exc))
            entry.failed(exc)
            entry.bytes_out += _send(tls, error_response(502, "resource unavailable"))
            return tls

        entry.bytes_out += _send(tls, response.raw)
        entry.served(response.status_code)
        return tls

    def _live_session(self, peer_ip: str) -> Session | None:
        """The live session that entitles `peer_ip` to this port, or None.

        Matched on all three of source IP, access port and protocol: the hole
        the SPA knock asked for and the Controller granted is a specific
        src -> port/proto, and a session opened for some other port is not
        authorisation for this one. Where several match, the one with the most
        lease left is used, so a client that re-knocked mid-connection is not
        bound to the lease that is about to expire.
        """
        candidates = [s for s in TABLE.active()
                      if s.client_ip == peer_ip
                      and s.access_port == self._port
                      and s.protocol == "tcp"
                      and not s.expired]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.remaining)


# -- socket helpers --------------------------------------------------------- #


def _close(sock: socket.socket | None) -> None:
    """Close without caring why it might fail. Called from finally blocks, so
    an exception here would mask the real one - and leak the descriptor."""
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _send(sock: socket.socket, payload: bytes) -> int:
    """Write a whole response, reporting how much reached the client.

    A client that hangs up early is ordinary, not an error worth unwinding a
    connection for, so a broken pipe counts as zero bytes out and the audit
    line still gets written.
    """
    try:
        sock.sendall(payload)
    except OSError as exc:
        status(log, "Client went away before the response was written", error=str(exc))
        return 0
    return len(payload)


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read up to and including the blank line.

    Returns (head, bytes-read-past-it). The cap is the inspector's, so a head
    that never ends is handed over as an incomplete one and refused by a rule
    instead of being special-cased here. Anything past the head is either the
    body or a pipelined second request; the body reader decides which.
    """
    buffer = bytearray()
    while len(buffer) < inspector.MAX_HEAD_BYTES:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, ssl.SSLError, OSError):
            break  # a client that stops talking gets the same refusal as a bad one
        if not chunk:
            break
        buffer += chunk
        if inspector.END_OF_HEAD in buffer:
            break
    head, separator, rest = bytes(buffer).partition(inspector.END_OF_HEAD)
    return head + separator, rest


def _read_body(sock: socket.socket, length: int, already: bytes) -> bytes:
    """Read exactly `length` body bytes, starting with what the head read ran on.

    Exactly, because "as much as arrives" is how a proxy and its upstream end
    up disagreeing about where a request ends. A client that closes early
    yields a short body, which the router then sends with the client's own
    Content-Length - so the resource sees the truncation rather than the
    Gateway inventing bytes. Anything beyond `length` is a pipelined request
    and is dropped: this proxy serves one request per connection.
    """
    if length <= 0:
        return b""
    buffer = bytearray(already[:length])
    while len(buffer) < length:
        try:
            chunk = sock.recv(min(65536, length - len(buffer)))
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buffer += chunk
    return bytes(buffer)
