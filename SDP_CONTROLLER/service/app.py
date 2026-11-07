"""The Controller's listener: HTTPS with mutual TLS, standard library only.

**Why this is a separate process at all.** The decision used to run inside the
Gateway (SDP_GATEWAY/controller/policy_controller.py), which meant the
component that enforces also decides. Anyone who owns the Gateway owns the
policy. Splitting them puts the policy file, the telemetry snapshot and the
trust scorer behind a network boundary the Gateway cannot cross except by
asking a question and reading an answer: it enforces, the Controller decides.

**Why the Gateway dials in and the Controller never dials out.** Exactly the
rule the IDP <-> Gateway link already follows
(IDENTITY_PROVIDER/api/gateway_link.py). Every inbound control connection in
the system therefore lands on one side — the IDP and the Controller — and the
Gateway, which is the component exposed to clients, has no control port for
anything to connect back to. A Controller that called the Gateway would also
need to know where every Gateway is; this way a Gateway only needs to know
where its Controller is.

**Why http.server and not FastAPI or uvicorn.** Two reasons, and the second is
the deciding one. The dependency surface of the component that holds the
policy is worth minimising. More importantly, the Controller's authorisation
model IS the peer certificate: the only thing that distinguishes a legitimate
Gateway from anything else on the network is the client certificate it
presents, and uvicorn does not hand the peer certificate to the application.
Python's own HTTP server does. The IDP's Gateway link reached the same
conclusion for the same reason.

**Why the handshake is deferred into the connection's own thread.** With
``do_handshake_on_connect=False`` the TLS handshake runs in the handler thread
(see handlers.ControllerRequestHandler.handle), not in the accept loop, so a
peer that opens a socket and then sends nothing stalls only itself. An
unsigned client never gets past that handshake, so it never reaches a route —
the refusal is in the TLS layer, not in application code that could have a bug
in it.
"""

from __future__ import annotations

import socket
import ssl
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING

from service.handlers import ControllerRequestHandler
from shared.ca import cert_utils
from shared.utils.logger import get_logger, status

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    # The transport layer knows the engine by its two methods and nothing
    # else, so it carries no runtime import of decision.py. main.py is the one
    # place that binds the concrete engine to this server.
    from decision import PolicyEngine

log = get_logger("Ctl-HTTP")

# How many connections the kernel may queue before they are accepted. A
# Gateway re-uses its connection across knocks (HTTP/1.1 keep-alive), so this
# is really "how many Gateways may arrive at once", not a request rate.
REQUEST_QUEUE_SIZE = 32


class ControllerNotConfigured(RuntimeError):
    """The certificate bundle the mTLS listener needs is incomplete.

    Its own type because it is not a programming error and not a transient
    one: the operator has to issue or copy a file. main.py turns it into a
    startup refusal with a non-zero exit.
    """


def ssl_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """The Controller's server side of the link, or a refusal naming what is missing.

    The existence check is here rather than left to ``load_cert_chain`` so the
    operator is told which of the three files is absent instead of reading a
    bare ``FileNotFoundError``. The context itself comes from
    shared/ca/cert_utils.py: TLS 1.3 minimum, and ``verify_mode =
    CERT_REQUIRED`` with the project CA loaded, which is what makes an
    unsigned client unable to complete a handshake.
    """
    paths = {"certificate": cert_path, "private key": key_path, "CA certificate": ca_path}
    missing = [f"{what} ({where})" for what, where in paths.items() if not Path(where).exists()]
    if missing:
        raise ControllerNotConfigured(
            "Controller certificate bundle missing: " + ", ".join(missing)
            + " - on the CA machine run `admin_cli.py init-ca`, then issue a server"
              " certificate for this host with SAN sdp-controller, localhost, 127.0.0.1"
              " and copy it here as controller.crt / controller.key / ca.crt")
    return cert_utils.server_context(cert_path, key_path, ca_path)


class ControllerServer(ThreadingHTTPServer):
    """A threading HTTPS server carrying the policy engine and the TLS context.

    Both live on the server rather than on the handler because socketserver
    builds a handler per request and gives it no room for arguments; handlers
    reach the engine through ``ControllerRequestHandler.engine``.
    """

    daemon_threads = True
    # A restart must not be blocked for the kernel's TIME_WAIT interval by
    # sockets the previous process left behind - a Controller that cannot bind
    # is a Gateway that denies every knock.
    allow_reuse_address = True
    request_queue_size = REQUEST_QUEUE_SIZE

    engine: PolicyEngine

    def __init__(self, server_address: tuple[str, int], engine: PolicyEngine,
                 ctx: ssl.SSLContext) -> None:
        # Both assigned before super().__init__, which binds AND activates the
        # socket: nothing may be accepted while the engine or the context is
        # still unset.
        self.engine = engine
        self._ctx = ctx
        super().__init__(server_address, ControllerRequestHandler)

    def get_request(self) -> tuple[socket.socket, tuple]:
        """Accept a connection and wrap it in TLS, without handshaking yet.

        ``do_handshake_on_connect=False`` is the whole point: the handshake is
        the expensive, attacker-controlled part, and running it here would run
        it in the accept loop. The handler does it in its own thread instead.
        """
        sock, addr = self.socket.accept()
        return (self._ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False),
                addr)

    def handle_error(self, request, client_address) -> None:
        """Keep a failed connection from printing a traceback to stderr.

        handlers.py already logs every refusal and every unhandled exception
        through the shared logger. socketserver's default would duplicate that
        in a different format, and a TLS failure is a routine event here, not
        an incident.
        """
        peer = client_address[0] if client_address else "unknown"
        log.debug("connection from %s ended with an exception", peer, exc_info=True)


def build(host: str, port: int, engine: PolicyEngine, ctx: ssl.SSLContext) -> ControllerServer:
    """Bind the listener. Raises OSError if the address is unavailable.

    Binding is split from serving so a caller - the entrypoint, or a test -
    can read the real port out of ``server.server_address`` before any request
    is served. That is what makes ``port=0`` usable, and it reports a bind
    failure as a startup failure rather than from inside the run loop.
    """
    try:
        server = ControllerServer((host, port), engine, ctx)
    except OSError as exc:
        status(log, "Bind failed", host=host, port=port, error=str(exc))
        raise
    bound_host, bound_port = server.server_address[:2]
    status(log, "Listener bound", host=bound_host, port=bound_port,
           protocol="https (mutual TLS, project CA)")
    return server


def serve(server: ControllerServer) -> None:
    """Run until interrupted, then shut down cleanly.

    ``server_close`` in the ``finally`` matters more than it looks: without it
    a listening socket can survive the process, and the next start fails to
    bind for reasons nothing in the log explains.
    """
    host, port = server.server_address[:2]
    status(log, "Controller serving", host=host, port=port,
           routes="POST /spa_verify, POST /session_review, GET /healthz")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        status(log, "Interrupted - shutting down")
    finally:
        stop(server)


def serve_in_background(server: ControllerServer, name: str = "controller-http") -> threading.Thread:
    """Serve in a daemon thread and return it.

    For a caller that owns the main thread: a test that then makes requests of
    its own, or a future embedding of the Controller in a larger process. The
    thread is a daemon so a caller that forgets ``stop()`` still exits.
    """
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    status(log, "Controller serving (background thread)", host=host, port=port)
    return thread


def stop(server: ControllerServer) -> None:
    """Stop accepting, let in-flight handlers finish, close the socket.

    Safe to call twice: ``shutdown`` on a server that is not serving returns
    immediately, and ``server_close`` on a closed socket is a no-op.
    """
    server.shutdown()
    server.server_close()
    status(log, "Controller stopped")


def run(host: str, port: int, engine: PolicyEngine, ctx: ssl.SSLContext) -> None:
    """Bind and serve. The entrypoint's one call."""
    serve(build(host, port, engine, ctx))


def resolve_bind_host(host: str) -> str:
    """Report what a bind host actually means, for the startup banner.

    ``0.0.0.0`` reads as "anywhere", which is alarming until you remember
    that every listener here is behind mutual TLS - reaching the port buys
    nothing without a CA-signed client certificate. Naming the host makes the
    line say which machine is offering the decision service.
    """
    if host in ("", "0.0.0.0"):
        return f"all interfaces (host {socket.gethostname()})"
    return host
