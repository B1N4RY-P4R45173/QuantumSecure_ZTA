"""The listener: plain HTTP, one thread per connection, standard library only.

**Why no TLS here.** The Gateway in front of this node is a terminating
proxy, the ZIA-PSE pattern: it ends the client's TLS session on
``sdp-gateway:443``, inspects the decrypted bytes, and re-forwards them over
a NEW connection to ``resource-node:7443``. That inner leg is cleartext on
purpose. It lives on data-plane-net, which is a compose ``internal: true``
bridge with no route to anything but the Gateway, and the resource node has
no route to the IDP at all. Running TLS on the inner leg would mean issuing
the resource a certificate, teaching the Gateway to trust it, and gaining
confidentiality against an attacker who, to be positioned at all, must
already be inside the segment. The segment boundary is the control; the
inner leg is plain.

**Why ThreadingHTTPServer and not asyncio, FastAPI or uvicorn.** This is the
most exposed component in the topology, so its dependency surface is the
thing worth minimising: ``http.server`` plus PyJWT plus cryptography, and
nothing that pulls a web framework and an ASGI server behind it. Threads
rather than a single loop because a stalled client must not stop the node
answering anyone else — and ``ThreadingHTTPServer`` gets that in one line,
where an async rewrite would buy throughput this node will never need.

``daemon_threads`` is on so a shutdown is not held hostage by an idle
keep-alive connection; ``REQUEST_TIMEOUT_SECONDS`` in endpoints.py is what
bounds how long such a thread can sit there in the first place.
"""

from __future__ import annotations

import socket
from http.server import ThreadingHTTPServer

from server.endpoints import ResourceContext, ResourceRequestHandler
from shared.utils.logger import get_logger, status

log = get_logger("Resource")

# How many connections the kernel may queue before the node is accepting
# them. The Gateway is the only client, but it re-forwards every client
# request on its own connection, so the queue is per-request in practice.
REQUEST_QUEUE_SIZE = 64


class ResourceServer(ThreadingHTTPServer):
    """A threading HTTP server that carries the resource context.

    The context is attached to the server rather than passed to the handler
    because socketserver constructs a handler per request and gives it no
    room for arguments. Handlers read it through
    ``ResourceRequestHandler.context``.
    """

    daemon_threads = True
    # A restart must not be blocked for the kernel's TIME_WAIT interval by
    # sockets the previous process left behind.
    allow_reuse_address = True
    request_queue_size = REQUEST_QUEUE_SIZE

    context: ResourceContext

    def __init__(self, server_address: tuple[str, int], context: ResourceContext) -> None:
        # Assigned before super().__init__, which binds and activates the
        # socket: nothing may be accepted while the context is still unset.
        self.context = context
        super().__init__(server_address, ResourceRequestHandler)


def build(host: str, port: int, context: ResourceContext) -> ResourceServer:
    """Bind the listener. Raises OSError if the address is unavailable.

    Binding is separated from serving so a caller — the entrypoint, or a test
    — can learn the real port (``server.server_address``) before any request
    is served, and so a bind failure is reported as a startup failure rather
    than from inside the run loop.
    """
    try:
        server = ResourceServer((host, port), context)
    except OSError as exc:
        status(log, "Bind failed", host=host, port=port, error=str(exc))
        raise
    bound_host, bound_port = server.server_address[:2]
    status(log, "Listener bound", host=bound_host, port=bound_port,
           protocol="http (plaintext, inner leg)", resource=context.name)
    return server


def serve(server: ResourceServer) -> None:
    """Run until interrupted, then close every connection cleanly.

    ``server_close`` in the ``finally`` matters more than it looks: without
    it a listening socket survives the process on some platforms, and the
    next start fails to bind for reasons nothing in the log explains.
    """
    host, port = server.server_address[:2]
    status(log, "Resource node serving", host=host, port=port,
           routes="GET /api/data, GET /healthz")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        status(log, "Interrupted - shutting down")
    finally:
        server.shutdown()
        server.server_close()
        status(log, "Resource node stopped")


def run(host: str, port: int, context: ResourceContext) -> None:
    """Bind and serve. The entrypoint's one call."""
    serve(build(host, port, context))


def resolve_bind_host(host: str) -> str:
    """Report what a bind host actually means, for the startup banner.

    ``0.0.0.0`` reads as "anywhere", which on a container attached only to
    data-plane-net means "the Gateway, and nothing else can route here" — the
    distinction an operator reading the log wants, since the same value would
    be alarming on a host with a public interface.
    """
    if host in ("", "0.0.0.0"):
        return f"all interfaces (container {socket.gethostname()})"
    return host
