# SDP Gateway (Accepting Host)

The Policy Enforcement Point. Holds protected resources dark by default,
admits a client only on a valid post-quantum knock, terminates and inspects
its TLS, and re-forwards the request inward.

## What it does

| Stage | Where | Behaviour |
|---|---|---|
| Default DROP | `firewall/rules.py` | nftables (or iptables) chain; protected ports answer nothing |
| SPA knock | `spa/listener.py` | ML-KEM-768 over one UDP datagram on `:62201` |
| Knock guards | `spa/guard.py` | Per-IP rate limit, replay cache, clock-skew freshness, one-time ticket ids |
| Decision | `controller/policy_controller.py` | Real trust score + `policies.yaml`, 13 rules |
| Pinhole | `firewall/sessions.py` | Source-pinned lease with a TTL and a reaper |
| TLS proxy | `proxy/handler.py` | Terminates on `:443`, inspects plaintext, relays to the resource |
| Inspection | `traffic/inspector.py` | Size caps, path traversal, SQLi and XSS markers |
| Re-evaluation | `controller/policy_controller.py` | Live sessions re-scored every 10 s and revoked if they now fail |

The IDP link (`mtls/idp_link.py`) is outbound only: the Gateway registers its
ML-KEM public key and fetches the JWKS over mTLS. The IDP never calls in.

## Enforcement modes

Detected at startup and stated in the log, because a Gateway that silently
enforces nothing looks identical to one that works.

| Mode | When | Behaviour |
|---|---|---|
| nftables | root + `nft` | Real kernel rules |
| iptables | root, no `nft` | Real kernel rules |
| dry-run | otherwise, or `GATEWAY_FORCE_DRY_RUN=1` | Same decisions and session table; logs the rules it would install |

Dry-run is not a weaker security posture for the data path: the proxy's
session check is in-process, so a connection is still bound to a live SPA
session even with no kernel rule behind it.

## On protocol-agnosticism — a claim this README used to make

Earlier versions of this file said the Gateway was **protocol-agnostic**:
that enforcing at L3/L4 let the same code front SSH, HTTPS and an IoT sensor
without parsing any of their protocols.

**That is no longer true, and it was removed rather than softened.** The
Gateway now terminates TLS and inspects the decrypted request, which is the
ZIA PSE pattern. A decrypting proxy must understand what it carries. What
survives of the original property is only this:

* **Admission is still protocol-agnostic.** The SPA knock, the pinhole and
  the lease are pure L3/L4 and work for any TCP or UDP service.
* **The data path is not.** `proxy/` and `traffic/` speak HTTP. An SSH or
  raw-IoT service behind this Gateway would be admitted correctly and then
  fail at the proxy.

Reaching a non-HTTP service would mean either a passthrough mode that skips
inspection, or a per-protocol handler. Neither exists.

## A weighting weakness, stated rather than buried

Device posture is worth 60 of the 100 trust points; Suricata and the ML
detector together are worth 40. A fully attested device therefore scores 60
even with a critical malware signature **and** every flow classified
malicious — above the threshold that `allow-employee-standard` needs — and
keeps its access.

The detection layer cannot, by itself, deny a healthy device. Whether that
is the right balance is a weighting question that a sensitivity analysis has
to answer. `tests/test_continuous_reevaluation.py::test_full_posture_outweighs_both_detectors`
pins the behaviour so a change to it is deliberate.

## Running it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python main.py
```

It needs, and fails closed without:

* `certs/pki/` holding `ca.crt`, `gateway.crt`/`.key` (the IDP link) and
  `proxy.crt`/`.key` (presented to clients). Issue them from the IDP with
  `admin_cli.py init-ca`, `issue-gateway-cert --id gw-1`,
  `issue-proxy-cert --id gw-1`, then copy the bundle here.
* A reachable IDP. Startup aborts if the JWKS cannot be fetched, because
  without it no knock can be verified.

`proxy.key` decrypts every client's traffic. It is the most sensitive key on
this host.

Under Docker the container needs `NET_ADMIN` (firewall) and
`NET_BIND_SERVICE` (port 443); `docker-compose.yml` grants both as named
capabilities rather than `--privileged`.

## Tests

```bash
PYTHONPATH="$(cd .. && pwd):$PWD:$(cd ../resource-node && pwd)" \
  .venv/bin/python -m pytest tests/ -q
```

66 tests. `conftest.py` forces dry-run before `firewall.rules` is imported,
so a run as root cannot insert live rules and leave them behind.

## Not built

* **No evidence channel to a Controller.** Re-evaluation works because the
  Controller runs in this process. A remote Controller would need the
  `SPA_VERIFY`/`APPROVED` IPC in `controller/client.py` carried over mTLS.
* **No real detector.** The ML and Suricata signals come from a telemetry
  snapshot file. The trained FLAT_cal model and the autoencoder in `MODELS/`
  are not wired in, and Suricata is not installed in the image.
* **Posture is not re-read mid-session.** It arrives attested inside a knock
  ticket; the admission-time value is carried forward, so a device whose
  posture decays is caught at its next knock.
