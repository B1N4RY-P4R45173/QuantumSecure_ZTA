"""Protected resource node entrypoint.

The thing the whole architecture exists to protect, and the only component
with no outbound trust at all. It is attached to data-plane-net and nothing
else: no route to the IDP, no route to the Controller, no route to the
client. The Gateway terminates the client's TLS, inspects the plaintext, and
re-forwards it here over the internal leg, so every request this node ever
sees arrives from the Gateway.

That isolation is why the node still verifies for itself. It cannot ask the
IDP whether a token is good, so it holds the IDP's RS256 PUBLIC key as a file
and checks the signature offline (access/guard.py). Two properties follow,
and both are the point:

  * The Gateway is not trusted to have checked. A Gateway that was
    compromised, or simply misconfigured to forward without inspecting,
    cannot conjure a request this node will serve — it would have to forge an
    RS256 signature.
  * There is nothing here worth stealing. A copy of the public key mints no
    tokens. The asymmetry is what makes distributing trust to the most
    exposed component safe.

Startup fails closed. Without a usable verification key the node cannot make
an authorization decision, so it refuses to start rather than start and 401
everything — the same posture the Gateway takes when the IDP serves it an
empty JWKS.
"""

import os
import sys

# This component's own directory is the import root — modules here import each
# other as top-level packages (``from access import guard``), not as
# resource_node.access, which the hyphen in the directory name would forbid
# anyway — and the repo root one level up makes ``shared`` importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from access import guard
from server import app
from server.endpoints import ResourceContext
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Resource")

COMPONENT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Bind host and port. 7443 is the inner-leg port the Gateway re-forwards to
# and the client never dials; see .env.example (RESOURCE_PORT).
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 7443

# The IDP's RS256 public key, copied in by the operator. Relative paths
# resolve against this component's directory, not the process working
# directory — see _resolve().
DEFAULT_PUBLIC_KEY_PATH = "./certs/idp_jwt_public.pem"

# Reported in the `resource` field of every /api/data response, so an
# operator reading a client's output can tell which node served it. A label,
# not a credential.
DEFAULT_RESOURCE_NAME = "resource-node"


def _resolve(path: str) -> str:
    """Make a relative configured path relative to this component.

    The defaults in .env.example are written component-relative (``./certs/
    ...``), which only lines up with the process working directory when the
    node happens to be started from its own folder. Anchoring to the file's
    own directory means the same .env works whether the node is started from
    the repo root, from resource-node/, or as /app/resource-node/main.py in
    the container.
    """
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(COMPONENT_ROOT, path))


def _port() -> int:
    raw = os.environ.get("RESOURCE_PORT", str(DEFAULT_PORT)).strip()
    try:
        port = int(raw)
    except ValueError:
        raise ValueError(f"RESOURCE_PORT is not a number: {raw!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"RESOURCE_PORT out of range: {port}")
    return port


def build_context() -> ResourceContext:
    """Resolve configuration into the immutable context the handler reads.

    Raises FileNotFoundError or ValueError when the verification key is
    missing or unusable. The caller treats either as fatal.
    """
    key_path = _resolve(os.environ.get("RESOURCE_JWT_PUBLIC_KEY_PATH",
                                       DEFAULT_PUBLIC_KEY_PATH).strip()
                        or DEFAULT_PUBLIC_KEY_PATH)
    name = os.environ.get("RESOURCE_NAME", DEFAULT_RESOURCE_NAME).strip() \
        or DEFAULT_RESOURCE_NAME
    # The audience the access token must name. The IDP stamps both its own
    # audience and this one into every access token, so the value here has to
    # match IDP_RESOURCE_AUDIENCE on the IDP exactly; shared settings reads
    # the same variable on both sides.
    audience = settings.idp_resource_audience
    authority = guard.load_authority(key_path, audience)
    return ResourceContext(name=name, authority=authority)


def main() -> int:
    host = os.environ.get("RESOURCE_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST
    status(log, "=" * 60)
    status(log, "PROTECTED RESOURCE NODE STARTING")
    status(log, "Transport: plain HTTP (the Gateway terminates TLS and re-forwards)")
    status(log, "Token validation: offline, RS256, no route to the IDP")
    status(log, "=" * 60)

    try:
        port = _port()
    except ValueError as exc:
        status(log, "ABORT: bad port configuration", error=str(exc))
        return 2

    try:
        context = build_context()
    except (FileNotFoundError, ValueError, OSError) as exc:
        # Fail closed: see the module docstring.
        status(log, "ABORT: cannot verify tokens", error=str(exc))
        return 1

    status(log, "Configuration resolved", resource=context.name,
           bind=f"{app.resolve_bind_host(host)}:{port}",
           audience=context.authority.audience,
           key=context.authority.key_path)

    try:
        app.run(host, port, context)
    except OSError as exc:
        status(log, "ABORT: could not listen", host=host, port=port, error=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
