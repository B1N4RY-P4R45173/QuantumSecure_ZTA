"""SDP Gateway entrypoint.

Identity comes from the standalone IDP and never from a Controller, which is
where this differs from classic SDP. Two things have to line up before the
SPA listener can do its job, and both go over the one IDP <-> Gateway link,
which is mutual TLS with the project CA (mtls/idp_link.py). The Gateway opens
that connection; the IDP never calls the Gateway.

  1. The client needs this Gateway's ML-KEM public key in order to
     encapsulate a knock against it. The client only ever talks to the IDP
     and the Gateway, so the IDP is what hands that key over, alongside the
     tokens. The Gateway registers the key with the IDP at startup; the IDP
     files it under the Gateway id in this Gateway's certificate.

  2. The Gateway must verify the knock ticket carried inside each knock. It
     fetches the IDP's JWKS (which holds the ES256 ticket key) for that, over
     the same link, so a forged JWKS cannot be slipped in on the way.

A knock that passes every Gateway check is forwarded to a Controller for the
access decision (controller/). Which Controller is a startup choice, and the
only one that matters for where policy lives:

  * GATEWAY_CONTROLLER_URL set - a separate Controller service, reached over
    mutual TLS (controller/remote.py). The Gateway enforces and nothing more.
    Startup aborts if that Controller is not answering, for the same reason
    the JWKS check aborts: a Gateway that cannot obtain a decision can admit
    nobody, so an open SPA port would only produce silent denials.
  * otherwise - the in-process policy engine (controller/policy_controller.py),
    which decides on this box.
  * GATEWAY_ALLOW_ALL=1 - the allow-all stand-in, for separating a data-path
    problem from a policy one during a demo. Never a default.

The startup log says which one plainly. "Decisions are made here" and
"decisions are made elsewhere" are different systems to operate, and that
difference must not be something an operator has to infer from a config file.
"""

import os
import sys
import threading

# Make the shared/ package (project root, one level up) importable. Each
# component runs with its own directory as the import root (`from spa import
# ...`, not SDP_GATEWAY.spa), so `shared` is reached through this bootstrap.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.allow_all import AllowAllController
from controller.policy_controller import PolicyController
from controller.remote import RemoteController
from firewall import rules as firewall_rules
from firewall.sessions import TABLE as sessions
from mtls import idp_link
from pqc import kem
from proxy.handler import InspectingProxy, ProxyNotConfigured
from spa.listener import SPAListener
from shared.ca.cert_utils import fingerprint
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Gateway")

# Service ports held dark until a knock opens them. Only enforced on the
# nftables backend; the iptables chain already ends in a blanket DROP.
PROTECTED_PORTS = [int(p) for p in
                   os.environ.get("GATEWAY_PROTECTED_PORTS", "22,80,443").split(",") if p.strip()]

# How often live sessions are re-scored against current evidence. This is the
# interval over which a device that becomes untrustworthy keeps its access,
# so it is a security parameter, not a tuning knob: shorter means a tighter
# window and more policy evaluations per second.
REEVALUATE_EVERY_SECONDS = float(os.environ.get("GATEWAY_REEVALUATE_SECONDS", "10"))

# Where the separate Controller service listens, e.g.
# https://sdp-controller:9500. Unset means the decision is made in process.
# Read here rather than inside the controller so the choice is visible at the
# top of the entrypoint that makes it.
CONTROLLER_URL = os.environ.get("GATEWAY_CONTROLLER_URL", "").strip()


def _reevaluation_loop(controller, stop: threading.Event) -> None:
    """Re-score live sessions until told to stop.

    Runs in its own thread so a slow policy evaluation cannot stall the SPA
    listener. Never lets an exception kill the loop: a Gateway that silently
    stopped re-evaluating would look healthy while quietly reverting to
    authorise-once.
    """
    while not stop.wait(REEVALUATE_EVERY_SECONDS):
        try:
            controller.reevaluate()
        except Exception as exc:
            status(log, "Re-evaluation pass failed", error=f"{type(exc).__name__}: {exc}")


def _check_idp_jwks(ctx) -> None:
    """Startup fails closed: without the IDP's signing keys the Gateway cannot
    verify a single knock, so opening the SPA port would be meaningless."""
    keys = idp_link.fetch_jwks(ctx).get("keys", [])
    if not keys:
        raise RuntimeError("IDP served an empty JWKS - aborting startup")
    if not any(k.get("alg") == "ES256" for k in keys):
        raise RuntimeError("IDP JWKS has no ES256 knock-ticket key - aborting startup")
    status(log, "IDP JWKS fetched over mTLS", keys=len(keys),
           kids=[k.get("kid") for k in keys])


def _check_controller(controller: RemoteController) -> None:
    """Startup fails closed, exactly as _check_idp_jwks does: a Gateway that
    cannot reach its Controller can approve no knock, so opening the SPA port
    would advertise a service that denies everything while looking healthy.
    Checked once here so the failure arrives at startup with a reason, rather
    than later as an unexplained refusal per knock."""
    reply = controller.check_healthz()
    status(log, "Controller reachable over mTLS", url=controller.url,
           health=reply.get("status"))


if __name__ == "__main__":
    status(log, "=" * 60)
    status(log, "SDP GATEWAY STARTING")
    status(log, f"IDP link: {settings.gateway_idp_link_url} (mTLS)")
    status(log, "=" * 60)

    kem_private_key, kem_public_key = kem.load_or_generate_keypair(
        settings.kem_private_key_path, settings.kem_public_key_path,
    )
    # Compare with `admin_cli.py list-gateways` on the IDP: a mismatch means
    # clients are encrypting knocks to a key this Gateway does not hold.
    status(log, "ML-KEM public key", alg=kem.ALG_NAME, fingerprint=fingerprint(kem_public_key))

    ctx = idp_link.ssl_context()
    idp_link.register_kem_key(kem_public_key, settings.gateway_spa_port, ctx)
    _check_idp_jwks(ctx)

    # Say plainly whether packets are actually being filtered. In dry-run the
    # whole SPA path still runs and the session table is still kept, so the
    # flow can be exercised off-box; nothing reaches the kernel.
    firewall_rules.ensure_chain()
    firewall_rules.protect_ports(PROTECTED_PORTS)
    status(log, "Firewall backend", mode=firewall_rules.mode(),
           enforcing=firewall_rules.mode() != firewall_rules.MODE_DRY_RUN,
           protected_ports=PROTECTED_PORTS)

    # One reaper for every lease, instead of a timer per grant.
    sessions.start_reaper()

    # Who decides. GATEWAY_ALLOW_ALL=1 is checked first and on purpose: it is
    # the escape hatch for isolating a data-path problem from a policy one
    # during a demo, so it has to win over whatever else is configured, and it
    # is never the default, because a Gateway that silently approves everything
    # looks identical to one that is working. Otherwise a Controller URL means
    # the decision is made off-box and this process only enforces; with no URL
    # the in-process engine decides here.
    if os.environ.get("GATEWAY_ALLOW_ALL") == "1":
        controller = AllowAllController()
        status(log, "Controller: allow-all stand-in (GATEWAY_ALLOW_ALL=1, NO POLICY ENGINE)")
    elif CONTROLLER_URL:
        controller = RemoteController(CONTROLLER_URL)
        # Before the SPA port opens, not after: see _check_controller.
        _check_controller(controller)
        status(log, "Controller: REMOTE - decisions are made by the Controller service, "
                    "this Gateway only enforces", url=CONTROLLER_URL)
    else:
        controller = PolicyController()
        status(log, "Controller: IN-PROCESS policy engine + trust scorer - "
                    "decisions are made by this Gateway")

    # The data path. Terminates the client's TLS, inspects the decrypted
    # request, and re-forwards it to the resource over the cleartext inner
    # leg. It refuses any peer without a live SPA session, so it cannot be
    # reached by knocking alone.
    proxy = None
    try:
        proxy = InspectingProxy()
        proxy.start()
        status(log, "TLS proxy started", port=settings.client_access_port,
               upstream=f"{os.environ.get('RESOURCE_HOST', 'resource-node')}:"
                        f"{os.environ.get('RESOURCE_PORT', '7443')}")
    except ProxyNotConfigured as exc:
        # No proxy certificate yet. The control plane still works, so the SPA
        # flow can be demonstrated; say plainly that the data path is down
        # rather than letting it look healthy.
        status(log, "TLS proxy NOT started - data path unavailable", reason=str(exc))

    # Continuous re-evaluation. Without this a grant is only ever judged at
    # admission, which is the behaviour of a firewall rule rather than of a
    # policy decision. The allow-all stand-in has nothing to re-evaluate.
    stop_reevaluation = threading.Event()
    reevaluator: threading.Thread | None = None
    if hasattr(controller, "reevaluate"):
        reevaluator = threading.Thread(
            target=_reevaluation_loop, args=(controller, stop_reevaluation),
            daemon=True, name="policy-reevaluate")
        reevaluator.start()
        status(log, "Continuous re-evaluation started",
               every=f"{REEVALUATE_EVERY_SECONDS:g}s")
    else:
        status(log, "Continuous re-evaluation NOT running - controller cannot re-score")

    listener = SPAListener(kem_private_key, idp_link.jwks_url(), controller, jwks_ssl_context=ctx)
    status(log, "SPA listener starting", port=settings.gateway_spa_port)
    try:
        listener.serve_forever()
    except KeyboardInterrupt:
        status(log, "Shutting down")
    finally:
        stop_reevaluation.set()
        # Close every lease and remove the chain, so a restart does not strand
        # accept rules in the kernel.
        if proxy is not None:
            proxy.stop()
        sessions.stop()
        firewall_rules.teardown()
        status(log, "Gateway stopped")
