# Threat Detection Approach — Zero Trust NIDS/IPS

**Project:** PQZTA — Tiered Zero Trust Intrusion Detection and Prevention System
**Document type:** Short technical report
**Date:** 16 October 2026
**Scope:** How one network connection is checked, from the moment it reaches an Edge Gateway until the Controller makes a decision.

---

## 1. Purpose

This report explains how the system finds two kinds of attacks:

| Attack type | Meaning | Main detector |
|---|---|---|
| **Known attack** | An attack that has been seen before and has a rule or a label | Suricata (at the gateway), XGBoost (at the controller) |
| **Unknown attack (zero-day)** | A new attack that has no rule and no label yet | Autoencoder and LSTM Autoencoder (at the controller) |

The main idea is a **funnel**. Cheap and certain checks run first, at the edge. Expensive and "smart" checks run last, at the controller.

---

## 2. System Overview

The system has two layers:

- **Edge Gateways (data plane):** They sit on the network. They see every packet at full speed (10–40+ Gbps). They run **Suricata**.
- **Controller Mesh (control plane):** A central group of servers. They receive **short summaries** of traffic from all gateways. They run the **ML models**.

Raw packets are **never** sent to the controller. Only small JSON summaries (about 350 bytes per connection) are sent. This saves bandwidth.

```
                 ┌──────────────────────── EDGE GATEWAY ────────────────────────┐
 Connection ───► │ Stage 0  Zero Trust access check                              │
                 │ Stage 1  IP reputation check          ┐                       │
                 │ Stage 2  Rate / volume check          ├─ Suricata (KNOWN)     │──► BLOCK / ALERT
                 │ Stage 3  Signature check (Hyperscan)  ┘                       │
                 │ Stage 4  Flow summary → eve.json → Log shipper                │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │  Kafka (secure tunnel, TLS)
                 ┌───────────────────────────────▼──────── CONTROLLER MESH ─────┐
                 │ Feature extraction (eve.json → numbers)                       │
                 │ Stage 5  XGBoost classifier        (KNOWN variants)  ┐ run in │
                 │ Stage 6  Autoencoder + LSTM-AE     (UNKNOWN attacks) ┘ parallel│
                 │ Stage 7  Cross-gateway correlation                            │
                 │ Stage 8  Decision and response                                │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │  Policy / new rule push
                                                 ▼
                              Stage 9  Feedback to all Edge Gateways
```

---

## 3. Step-by-Step Flow

### Stage 0 — Zero Trust Access Check (Gateway)
- **What:** Checks if this user or device is allowed to reach this service.
- **How:** Uses identity, device health and access policy.
- **Why first:** In Zero Trust, nothing is trusted by default. If access is denied, no attack check is needed.

### Stage 1 — IP Reputation Check (Gateway, Known)
- **What:** Checks if the source IP is on a list of known bad addresses.
- **How:** Suricata IP reputation lists, filled from threat-intelligence feeds.
- **Why here:** It is the cheapest check. It reads only the address, not the content.

### Stage 2 — Rate / Volume Check (Gateway, Known)
- **What:** Checks if one source sends too much, too fast.
- **How:** Suricata `threshold` and `rate_filter` with `track by_src`.
- **Catches:** SYN floods, brute-force logins, simple DoS attacks.
- **Why here:** Counting is cheap. It stops floods before they use up CPU.

### Stage 3 — Signature Check (Gateway, Known)
- **What:** Checks if the packet content matches a known attack pattern.
- **How:** Suricata rules with fast pattern matching (Hyperscan / Aho-Corasick).
- **Result:** A clear alert with a rule ID (SID) and often a CVE number.
- **Memory control:** Only the first part of each stream is inspected (`stream.reassembly.depth`, default 1 MB). This protects low-RAM gateways from large transfers (for example, a 5 GB file).

> Note: Inside Suricata, Stages 1–3 run inside one engine, not as fully separate steps. The order above is a design view.

### Stage 4 — Flow Summary and Transport (Gateway → Controller)
- When a connection ends (or times out), Suricata writes a **flow record** to `eve.json`.
- A log shipper (Filebeat, Fluent Bit or Vector) sends it through **Kafka** over a secure tunnel.
- All flow records are sent, including flows that Suricata alerted on. The field `flow.alerted` shows if Suricata raised an alert on that flow.

**Example flow record (shortened):**

```json
{
  "timestamp": "2026-10-16T10:15:02.123+0000",
  "event_type": "flow",
  "src_ip": "10.0.1.25", "src_port": 51544,
  "dest_ip": "10.0.5.10", "dest_port": 443,
  "proto": "TCP", "app_proto": "tls",
  "flow": {
    "pkts_toserver": 14, "pkts_toclient": 12,
    "bytes_toserver": 1830, "bytes_toclient": 9420,
    "start": "2026-10-16T10:14:58.001+0000",
    "end":   "2026-10-16T10:15:01.950+0000",
    "age": 4, "state": "closed", "reason": "timeout", "alerted": false
  },
  "tcp": { "tcp_flags": "1b", "syn": true, "fin": true, "psh": true, "ack": true }
}
```

### Feature Extraction (Controller)
The controller turns each JSON record into a list of numbers (a **feature vector**). Examples:

| Group | Example features |
|---|---|
| Size | `bytes_toserver`, `bytes_toclient`, byte ratio (out / in) |
| Packets | `pkts_toserver`, `pkts_toclient`, average packet size |
| Time | duration (`end − start`), bytes per second |
| Protocol | `proto`, `app_proto`, destination port group (encoded as numbers) |
| TCP | SYN / FIN / RST / PSH flags, end state |
| TLS (encrypted traffic) | JA3/JA4 fingerprint, SNI, certificate details (hashed or encoded) |
| Host window (for LSTM) | per source IP in N seconds: number of flows, unique destination IPs, unique ports, failed connections |

Numbers are **scaled** (for example, min-max or log scaling) so that large values like bytes do not dominate small values like flag counts.

### Stage 5 — XGBoost Classifier (Controller, Known Variants)
- **What:** Finds **known attack types that changed a little**, so no Suricata signature matches anymore.
- **Input:** Flow feature vector.
- **Output:** An attack class (for example, "port scan", "DoS", "normal") and a probability.
- **Type:** Supervised. It learns only from labelled examples. **It cannot find new attacks.**

### Stage 6 — Autoencoder and LSTM Autoencoder (Controller, Unknown)
- **What:** Finds traffic that looks **different from normal**.
- **Training:** Trained only on normal (benign) traffic. Flows with `flow.alerted = true` are **removed** from training data.
- **How it works:**
  1. The model squeezes the input into a small form and then tries to rebuild it.
  2. Normal traffic is rebuilt well, so the error is low.
  3. Strange traffic is rebuilt badly, so the error is high.
  4. The rebuild error is measured with **MSE** (Mean Squared Error).
  5. If MSE is above the **threshold**, the traffic is flagged as an anomaly.
- **Two models:**

| Model | Input | Finds |
|---|---|---|
| Autoencoder (dense) | One flow vector | One strange connection (for example, a very large upload) |
| LSTM Autoencoder | A sequence of host time windows (for example, 10 windows of 60 s) | Strange behaviour over time (slow scans, regular "beaconing", lateral movement) |

- **Threshold:** Set from the MSE of clean validation data, for example the 99th percentile. It is updated over time to follow normal changes in traffic.
- **Explanation:** The error is also checked **per feature**. The alert can then show which features were strange (for example, `bytes_toserver` and `dst_port`).

Stages 5 and 6 do not depend on each other, so they run **in parallel**.

### Stage 7 — Cross-Gateway Correlation (Controller)
- **What:** Checks if the same pattern appears on many gateways.
- **Example:** One IP touches 3 hosts on each of 50 gateways. Each gateway sees only 3, which looks normal. Together it is 150 hosts, which is a scan.
- **Why:** Only the controller has the full view of all gateways.

### Stage 8 — Decision and Response (Controller)
The scores from Suricata, XGBoost, the autoencoders and the correlation step are combined. The response is **step by step**:

| Confidence | Action |
|---|---|
| Low | Alert only (send to analyst / SIEM) |
| Medium | Rate-limit the source |
| High, or several detectors agree | Block the source, with an expiry time (TTL) |

**Safety rules:**
- Every block has a **TTL**, so it is removed automatically later.
- An **allowlist** protects critical servers from automatic blocking.
- Hard blocks need **more than one signal**, because attackers can fake (spoof) a source IP to make the system block a real server.

### Stage 9 — Feedback Loop (Controller → All Gateways)
When an unknown attack is confirmed:
1. A new **Suricata rule** is written and pushed to all gateways. Next time it is caught at Stage 3, in microseconds.
2. The labelled samples are added to the **XGBoost** training data.
3. The samples are **removed** from the autoencoder's normal training data.

Over time, unknown attacks become known attacks, and the system gets cheaper and faster.

---

## 4. Model Summary

| Detector | Location | Attack type | Learning type | Speed | Explainability |
|---|---|---|---|---|---|
| Suricata | Gateway | Known | Rules (no learning) | Microseconds, line rate | High (SID / CVE) |
| XGBoost | Controller | Known variants | Supervised | Very fast | Medium (feature importance) |
| Autoencoder | Controller | Unknown (single flow) | Unsupervised (normal only) | Fast | Medium (per-feature error) |
| LSTM Autoencoder | Controller | Unknown (over time) | Unsupervised (normal only) | Slower | Low–Medium |

---

## 5. Known Limits and How We Handle Them

| Limit | Risk | Mitigation |
|---|---|---|
| Suricata rules can be too broad | False alarms on normal traffic | Tune rules, track noisy SIDs |
| 1 MB inspection depth | Attack hidden after the first 1 MB | Use flow-shape features at the controller (for example, bytes after depth) |
| Flow record written at connection end | Long attack connections are seen late | Shorter flow timeouts; host time windows |
| "Normal" training data may contain missed attacks | Model learns attacks as normal | Remove alerted flows; train on checked periods; robust thresholds |
| Automatic blocking | Attacker spoofs IPs to block real servers | TTL, allowlist, multi-signal confirmation, step-by-step response |
| Encrypted traffic (TLS) | Signatures cannot read content | Use TLS metadata (JA3/JA4, SNI, certificate) as features |

---

## 6. Glossary

| Term | Simple meaning |
|---|---|
| **Data plane** | The part of the network that moves and checks packets |
| **Control plane** | The central part that makes decisions and sends policies |
| **Signature** | A rule that describes a known attack pattern |
| **Flow** | One network connection between two devices |
| **eve.json** | Suricata's output file, one JSON line per event |
| **Feature vector** | A list of numbers that describes one flow or one time window |
| **Supervised model** | Learns from labelled examples ("attack" / "normal") |
| **Unsupervised model** | Learns only from normal data, with no labels |
| **Autoencoder** | A neural network that compresses data and then rebuilds it |
| **MSE** | Mean Squared Error — how different the rebuilt data is from the original |
| **Threshold** | The limit above which MSE is called "strange" |
| **Zero-day attack** | A new attack that has no known rule yet |
| **TTL** | Time To Live — how long a rule stays active before it is removed |
| **False positive** | Normal traffic wrongly marked as an attack |
