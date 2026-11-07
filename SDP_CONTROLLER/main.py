"""SDP Controller entrypoint: the policy decision point, as its own service.

The decision used to run inside the Gateway. That put the component which
enforces and the component which decides in one process, so compromising the
Gateway compromised the policy itself. This process is the other half of that
split: it holds policies.yaml, the telemetry snapshot and the trust scorer,
and it answers two questions over mutual TLS.

    POST /spa_verify       a verified knock -> APPROVED or DENIED
    POST /session_review   the Gateway's live sessions -> the ones to revoke

The Gateway dials in; the Controller never dials out. Same rule as the IDP
<-> Gateway link, and deliberately so: every inbound control connection in
the system lands on the IDP or here, and the Gateway - the component exposed
to clients - offers no control port for anything to connect back to.

STARTUP FAILS CLOSED, and that is the point of this file.

A Controller that starts without its certificates would offer a port no
Gateway could authenticate to; a Controller that starts without its policy
file would answer questions with no policy behind the answers. Either one is
worse than not starting, because the Gateway's rule is that an unreachable
Controller denies: a Controller that is simply absent costs access, while a
Controller that is present and wrong costs the thing access control exists
for. So both are checked before the socket is bound, and a failure exits
non-zero with a sentence rather than a traceback - the same posture
resource-node/main.py takes with its verification key and the Gateway takes
with the IDP's JWKS.

What is NOT fatal: a missing telemetry snapshot. The scorer treats an absent
entry as unknown and awards half credit for it, which is a documented
decision and not an error. See SDP_CONTROLLER/trust_scorer.py.
"""

import os
import sys

# This component's own directory is the import root - modules here import each
# other as top-level packages (``from service import app``, ``from decision
# import PolicyEngine``), the way demo.py and run_pipeline.py already do - and
# the repo root one level up makes ``shared`` importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision import PolicyEngine
from service import app
from shared.utils.logger import get_logger, status

log = get_logger("Controller")

COMPONENT_ROOT = os.path.dirname(os.path.abspath(__file__))

# 9500 is the Controller's mTLS port, the one the Gateway dials. Nothing else
# in the topology connects to it: not a client, not the IDP, not a resource.
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9500

# The Controller's SERVER certificate, and the project CA it verifies Gateway
# certificates against. Relative paths resolve against this component's
# directory, not the process working directory - see _resolve().
DEFAULT_CERT_PATH = "./certs/pki/controller.crt"
DEFAULT_KEY_PATH = "./certs/pki/controller.key"
DEFAULT_CA_PATH = "./certs/pki/ca.crt"

# The policy the decisions are made against, and the detection pipeline's
# snapshot. Both already live in this component and are reloaded per decision
# by the engine, so an operator editing a rule does not restart anything.
DEFAULT_POLICIES_PATH = "./policies.yaml"
DEFAULT_TELEMETRY_PATH = "./telemetry_snapshot.json"


def _resolve(path: str) -> str:
    """Make a relative configured path relative to this component.

    The project's configured paths are written component-relative
    (``./certs/...``), which only lines up with the process working directory
    when the component happens to be started from its own folder. Anchoring to
    this file's directory means one configuration works whether the Controller
    is started from the repo root, from SDP_CONTROLLER/, or as
    /app/SDP_CONTROLLER/main.py in a container.
    """
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(COMPONENT_ROOT, path))


def _env_path(name: str, default: str) -> str:
    return _resolve(os.environ.get(name, default).strip() or default)


def _port() -> int:
    raw = os.environ.get("CONTROLLER_PORT", str(DEFAULT_PORT)).strip()
    try:
        port = int(raw)
    except ValueError:
        raise ValueError(f"CONTROLLER_PORT is not a number: {raw!r}") from None
    # 0 is allowed deliberately: it means "any free port", which is how a test
    # stands the service up without colliding with a running one.
    if not 0 <= port <= 65535:
        raise ValueError(f"CONTROLLER_PORT out of range: {port}")
    return port


def _ttl_seconds() -> int | None:
    """The grant lifetime, or None to leave it to the engine's own default.

    Unset means unset: an entrypoint that substituted a number here would
    quietly override the lifetime the policy engine considers correct, and the
    log would show the Controller's default rather than the one in force.
    """
    raw = os.environ.get("CONTROLLER_TTL_SECONDS", "").strip()
    if not raw:
        return None
    try:
        ttl = int(raw)
    except ValueError:
        raise ValueError(f"CONTROLLER_TTL_SECONDS is not a number: {raw!r}") from None
    if ttl <= 0:
        raise ValueError(f"CONTROLLER_TTL_SECONDS must be positive: {ttl}")
    return ttl


def build_engine(ttl_seconds: int | None) -> PolicyEngine:
    """Load the policy engine, or raise.

    The policy file's existence is checked here rather than left to the engine
    so the operator is told the path that is missing. Everything the engine
    itself rejects - an unparseable rule, an expression it cannot evaluate -
    comes back as its own exception and is equally fatal: see the module
    docstring on why a Controller with no usable policy must not start.
    """
    policies_path = _env_path("CONTROLLER_POLICIES_PATH", DEFAULT_POLICIES_PATH)
    telemetry_path = _env_path("CONTROLLER_TELEMETRY_PATH", DEFAULT_TELEMETRY_PATH)
    if not os.path.exists(policies_path):
        raise FileNotFoundError(f"policy file not found: {policies_path}")
    if not os.path.exists(telemetry_path):
        # Not fatal. Said out loud anyway, because a score computed with no
        # detection evidence is a different number from one computed with it,
        # and an operator comparing two runs deserves to know which they got.
        status(log, "No telemetry snapshot - detection signals score as unknown",
               path=telemetry_path, hint="run SDP_CONTROLLER/run_pipeline.py to produce one")
    status(log, "Policy inputs resolved", policies=policies_path, telemetry=telemetry_path)
    return PolicyEngine(policies_path=policies_path, telemetry_path=telemetry_path,
                        ttl_seconds=ttl_seconds)


def main() -> int:
    host = os.environ.get("CONTROLLER_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST
    status(log, "=" * 60)
    status(log, "SDP CONTROLLER STARTING")
    status(log, "Role: policy decision point - it decides, the Gateway enforces")
    status(log, "Transport: HTTPS with mutual TLS; the Gateway dials in, never the reverse")
    status(log, "=" * 60)

    # Configuration errors are exit 2, missing or unusable inputs exit 1 - the
    # same split resource-node/main.py uses, so a supervisor can tell "fix the
    # environment" from "issue the certificate".
    try:
        port = _port()
        ttl = _ttl_seconds()
    except ValueError as exc:
        status(log, "ABORT: bad configuration", error=str(exc))
        return 2

    try:
        ctx = app.ssl_context(
            _env_path("CONTROLLER_TLS_CERT_PATH", DEFAULT_CERT_PATH),
            _env_path("CONTROLLER_TLS_KEY_PATH", DEFAULT_KEY_PATH),
            _env_path("CONTROLLER_CA_CERT_PATH", DEFAULT_CA_PATH),
        )
    except app.ControllerNotConfigured as exc:
        status(log, "ABORT: no mutual TLS, so no Gateway could authenticate", error=str(exc))
        return 1
    except OSError as exc:
        # An unreadable file or a key that does not match the certificate.
        # ssl.SSLError is an OSError, so this covers both. Fatal for the same
        # reason: without a usable server identity there is no link.
        status(log, "ABORT: certificate bundle unusable", error=f"{type(exc).__name__}: {exc}")
        return 1

    try:
        engine = build_engine(ttl)
    except Exception as exc:
        status(log, "ABORT: no usable policy, so no decision could be justified",
               error=f"{type(exc).__name__}: {exc}")
        return 1

    status(log, "Configuration resolved", bind=f"{app.resolve_bind_host(host)}:{port}",
           client_certificates="required, project CA only",
           ttl=f"{ttl}s" if ttl is not None else "engine default")

    try:
        app.run(host, port, engine, ctx)
    except OSError as exc:
        status(log, "ABORT: could not listen", host=host, port=port, error=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
