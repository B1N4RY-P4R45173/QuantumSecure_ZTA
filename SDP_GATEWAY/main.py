"""SDP Gateway entrypoint.

The Gateway consults the standalone IDP, never a Controller. Two things
have to line up before the SPA listener can do its job, and both go over
the one IDP <-> Gateway link, which is mutual TLS with the project CA
(mtls/idp_link.py). The Gateway opens that connection; the IDP never calls
the Gateway.

  1. The client needs this Gateway's ML-KEM public key in order to
     encapsulate a knock against it. The client only ever talks to the IDP
     and the Gateway, so the IDP is what hands that key over, alongside the
     tokens. The Gateway registers the key with the IDP at startup; the IDP
     files it under the Gateway id in this Gateway's certificate.

  2. The Gateway must verify the knock ticket carried inside each knock. It
     fetches the IDP's JWKS (which holds the ES256 ticket key) for that, over
     the same link, so a forged JWKS cannot be slipped in on the way.

A knock that passes every Gateway check is forwarded to a Controller for the
access decision (controller/). For now that is an in-process allow-all
stand-in; the real SDP Controller will replace it.
"""

import os
import sys

# Make the shared/ package (project root, one level up) importable. Each
# component runs with its own directory as the import root (`from spa import
# ...`, not SDP_GATEWAY.spa), so `shared` is reached through this bootstrap.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.allow_all import AllowAllController
from controller.policy_controller import PolicyController
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

    # The real decision maker: scores device trust and evaluates policies.yaml.
    # GATEWAY_ALLOW_ALL=1 falls back to the stand-in, for isolating a data-path
    # problem from a policy one during a demo. It is never the default, because
    # a Gateway that silently approves everything looks identical to one that
    # is working.
    if os.environ.get("GATEWAY_ALLOW_ALL") == "1":
        controller = AllowAllController()
        status(log, "Controller: allow-all stand-in (GATEWAY_ALLOW_ALL=1, NO POLICY ENGINE)")
    else:
        controller = PolicyController()
        status(log, "Controller: policy engine + trust scorer")

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

    listener = SPAListener(kem_private_key, idp_link.jwks_url(), controller, jwks_ssl_context=ctx)
    status(log, "SPA listener starting", port=settings.gateway_spa_port)
    try:
        listener.serve_forever()
    except KeyboardInterrupt:
        status(log, "Shutting down")
    finally:
        # Close every lease and remove the chain, so a restart does not strand
        # accept rules in the kernel.
        if proxy is not None:
            proxy.stop()
        sessions.stop()
        firewall_rules.teardown()
        status(log, "Gateway stopped")
