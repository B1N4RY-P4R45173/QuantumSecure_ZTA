# Zero Trust Network Access — Software Defined Perimeter

A Zero Trust Network Access (ZTNA) system built on the Cloud Security Alliance
**Software Defined Perimeter** model, with a NIST SP 800-207 compliant policy
engine and a dynamic trust algorithm driven by IDS + ML detection.

Enforcement happens at the packet-filter layer, so the system is
**protocol-agnostic** — the same gateway protects SSH, HTTPS, a Python service,
or an IoT device without knowing anything about their protocols.

---

## Components

| Directory | SDP role | NIST 800-207 role | Status |
|---|---|---|---|
| [`sdp-controller/`](sdp-controller/) | SDP Controller | Policy Engine + Trust Algorithm | ✅ **Built** |
| [`sdp-gateway/`](sdp-gateway/) | SDP Accepting Host (AH) | Policy Enforcement Point + Policy Administrator | ⬜ Planned |
| [`sdp-client/`](sdp-client/) | SDP Initiating Host (IH) | Subject / client agent | ⬜ Planned |

---

## Target architecture

```
   ┌──────────────┐                          ┌────────────────────┐
   │  SDP CLIENT  │───(1) authenticate──────▶│   SDP CONTROLLER   │
   │    (IH)      │                          │  PE + trust algo   │
   │              │◀──(2) signed authz───────│                    │
   └──────┬───────┘                          └─────────┬──────────┘
          │                                            │
          │ (3) SPA packet                    (4) "open pinhole
          │     (UDP, HMAC,                       src=X dst=22
          │      encrypted, nonce)                 ttl=300s"
          │                                            │
          ▼                                            ▼
   ┌───────────────────────────────────────────────────────────┐
   │                     SDP GATEWAY (AH)                      │
   │  nftables default DROP  →  dynamic pinhole on valid SPA   │
   │  ┌─────────────────────────────────────────────────────┐  │
   │  │  Gateway IDS + ML  (resource-directed attacks)       │──┼──▶ trust
   │  └─────────────────────────────────────────────────────┘  │   feedback
   └───────────────────────────┬───────────────────────────────┘
                               ▼
              PROTECTED RESOURCES (SSH / HTTPS / IoT / anything)
```

---

## Two-layer detection

The system runs detection in **two places**, answering different questions.
They are deliberately not redundant:

| | Controller-side (built) | Gateway-side (planned) |
|---|---|---|
| Question | *"Is this device compromised?"* | *"Is this session attacking the resource?"* |
| Sensor placement | Client network segment / endpoint | In front of the protected resource |
| ML features | Flow shape — packet counts, IAT, TCP flags | Session behaviour — request rate, access pattern |
| Model | RandomForest, 5-class | Anomaly detection + rate thresholds |
| Suricata rules | ET SCAN, ET MALWARE | ET WEB_SERVER, ET EXPLOIT, ET ATTACK_RESPONSE |
| Detects | Compromised endpoint, C2 beaconing, recon | SQLi, brute force, mass exfiltration |
| Acts on | Future authorizations | The live session, immediately |

The gap this closes: a device can be clean at authorization time and turn
malicious 20 minutes later inside an authorized session. Controller-side
detection cannot see that; gateway-side detection can.

---

## Quick start

Everything currently runnable lives in the controller:

```bash
cd sdp-controller
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m ml.generate_dataset && python -m ml.train

python run_pipeline.py --benign && python demo.py   # baseline
python run_pipeline.py --attack && python demo.py   # device compromised
```

Full instructions in [`sdp-controller/README.md`](sdp-controller/README.md).

---

## Roadmap

| Week | Focus | Deliverable |
|---|---|---|
| 1 | Policy engine | Rego-style PDP, YAML policies, deny-wins + implicit deny |
| 2 | Trust algorithm | Suricata parser, RandomForest flow classifier, fused 0–100 score |
| 3 | Gateway core (PEP) | nftables default-DROP, pinhole API with TTL, session table |
| 4 | SPA + client agent | Encrypted HMAC single-packet auth, replay protection |
| 5 | Controller ↔ Gateway | Signed short-lived tokens, mTLS, session lifecycle |
| 6 | Gateway-side IDS + ML | Second detection layer, trust feedback loop |
| 7 | Continuous evaluation | Live re-scoring, active session revocation mid-connection |
| 8 | ML depth | Real CIC-IDS2017, model comparison, ROC / PR analysis |
| 9 | Testbed + evaluation | Multi-VM deployment, latency and throughput measurements |

---

## Testbed topology

| VM | Role | Requirements |
|---|---|---|
| `client` | SDP Initiating Host | any Linux |
| `gateway` | SDP Accepting Host | **root** (nftables), Suricata, ideally two NICs |
| `controller` | Policy Engine + trust algorithm | Python 3.12+ |
| `resource` | Protected service (SSH / web / IoT) | any Linux |

The controller can be co-located with the gateway for a three-VM setup.
