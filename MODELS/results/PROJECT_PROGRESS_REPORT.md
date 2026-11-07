# Project Progress Report: Quantum Secure Zero Trust Architecture for IoT

Written 2026-11-06. This document collects **everything done so far, from the start**: the goal, every
phase, the problems we hit and the decisions we took to fix them, all results, and the study of the
**trust score engine** in the SDP Controller (done in the latest session).

All numbers come from real runs on PC 2 (`runs/<name>_<timestamp>/`) or from the code itself.
Nothing here is invented. Where something is an **assumption or my reading**, it says so.

---

## Contents
1. What the project is
2. Where things run (setup)
3. Timeline from the start
4. Network threat detection: phases, results, decisions
5. Final detection architecture
6. Trust score engine study (latest session)
7. Gap: detection work vs the trust scorer
8. All key decisions (one table)
9. Open items and next steps
10. Files and runs index
11. How to run

---

## 1. What the project is

A **Quantum Secure Zero Trust Architecture (ZTA)** for IoT. No device or user is trusted by default.
Every access request is checked again and again.

| Part | Folder | Job |
|---|---|---|
| SDP Client | `SDP_CLIENT/` | Device side: SPA knock (post-quantum ML-KEM), FIDO2 login, WireGuard tunnel, posture collection |
| Identity Provider | `IDENTITY_PROVIDER/` | Login (FIDO2/WebAuthn) |
| SDP Controller | `SDP_CONTROLLER/` | Brain: trust score + policy engine, decides ALLOW / DENY / MFA |
| SDP Gateway | `SDP_GATEWAY/` | Door in front of resources: opens/closes access, runs Suricata + ML |
| Resource node | `resource-node/` | The protected service |
| Shared code | `shared/` | CA, config, schemas (posture, policy, token), crypto, PQC SPA, knock tickets |
| ML research | `MODELS/` | Threat detection models and tests |

Technologies: SDP + SDN (Ryu, Open vSwitch), WireGuard, FIDO2/WebAuthn, Suricata IDS/IPS,
CICFlowMeter, PyTorch, XGBoost, LightGBM.

**Main research question of the ML part:** how to detect attacks in the traffic between
Client ↔ Controller and Client ↔ Resource, and stop them **before they reach the resource**, on an
IoT gateway with limited RAM and CPU.

---

## 2. Where things run (setup)

| Item | Value |
|---|---|
| PC 1 | Where Claude works. The project folder is mounted at `~/IOT_SERVER` |
| PC 2 | GPU server where everything runs: `/home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA` |
| GPUs | 2 × NVIDIA A2 (≈ 14.6 GB each), CUDA 12.9, PyTorch 2.11.0+cu128 |
| Rule | Claude writes scripts only; the user runs them on PC 2; Claude reads `runs/` afterwards |

Virtual environments (in `/home/abhinav_iot/`):

| Env | Use |
|---|---|
| `pqzta-venv` | **Default** for all ML training (xgboost, lightgbm, sklearn, pandas, torch, matplotlib) |
| `gpu-env` | GPU tests only |
| `cfm-py` | Python CICFlowMeter only (pcap → flow CSV) |

GPU check: `runs/gpu_check_20261030_205158/`: both A2 GPUs work with torch.

---

## 3. Timeline from the start

| Date | What happened |
|---|---|
| 2026-10-30 | Project rules written (`CLAUDE.md`), env check, GPU check OK, `CHECKLIST.md` created (phases 0–6) |
| 2026-10-30 | Phase 1 on TRUST Lab: window trade-off study for SW-XGBoost (windows 8…64) |
| 2026-10-30/31 | Balanced detector (single + time-series attacks) built; LightGBM version added |
| 2026-10-31 | LightGBM GPU crashed → trained on CPU. Chosen model: **LightGBM BAL_MS** |
| 2026-10-31 | Live latency test: fast live feature builder (8.2 ms → 0.25 ms per flow) |
| 2026-10-31 | CICFlowMeter 4.0 (Java) conversion of CIC-IDS2017; **data leak found** (6 bulk features) → retrained without them |
| 2026-10-31 | Java CFM counts payload, TRUST Lab counts full frame → **switched to Python cicflowmeter** |
| 2026-10-31 | CIC-IDS2017 Wednesday test: BAL_MS caught **0.13 %** → the TRUST Lab model does not transfer |
| 2026-11-02 | New training dataset **CICIoT2023** downloaded (309 files, 8.9 GB, Hugging Face, SHA-checked) |
| 2026-11-02 | Test dataset **Edge-IIoTset** downloaded (Kaggle archive, PCAPs) |
| 2026-11-02 | Trained FLAT + BAL_MS on CICIoT2023: BAL_MS 97.8 % detection, 2.3 % false alarms |
| 2026-11-04 | Edge-IIoTset inline test (Suricata + ML): **100 % false alarms** on new network → site calibration invented |
| 2026-11-04 | Calibration + autoencoder + quarantine rule tuned → **0 % attack reached resource, 0.5 % normal wrongly blocked** |
| 2026-11-04 | Handover document written (`HANDOVER_NETWORK_THREAT_DETECTION.md`) |
| 2026-11-05/06 | **Trust score engine study** (section 6) and this report |

---

## 4. Network threat detection: phases, results, decisions

### Phase 1: TRUST Lab dataset (known attacks)
* **Data:** TRUST Lab (UPCT 2025), 16 classes (Benign + 15 attacks), CICFlowMeter flow features (70).
* **Models compared:** XGBoost, LightGBM, LSTM (32 flows), sliding-window (SW) XGBoost/LightGBM.
* **Window study** (`sw_xgb_window_tradeoff_20261030_231549`, `sw_lgbm_window_tradeoff_20261031_004422`):
  a bigger window gives fewer false alarms and better time-series attacks, but hidden single attacks
  fall from 99.7 % to ≈ 91 %.
* **Problem:** models were good at either single attacks or time-series attacks, not both.
  **Fix:** "balanced" model BAL_MS = current flow + window 8 + window 56 + deviation, trained with
  solo attacks hidden among normal flows.
* **Problem:** LightGBM GPU learner crashed (`best_split_info.left_count > 0`). **Fix:** train on CPU.
* **Problem:** live feature building took 8.2 ms per flow (gateway buffer would overflow).
  **Fix:** numpy ring-buffer builder `MODELS/common/live_windows.py`: 100 % the same predictions,
  248 µs per flow, ≈ 4,000 flows/s on 1 thread.
* **Problem (data leak):** 6 "bulk" features were always 0 in 5 classes (old CICFlowMeter version)
  and non-zero in the other 10, so the model could learn the tool version instead of the attack.
  **Fix:** retrain without them (`--drop-bulk`). Detection did not drop → the leak did not inflate results.

**Phase 1 choice: LightGBM BAL_MS, no bulk features** (`sw_lgbm_balanced_nobulk_20261031_121031`)

| Metric | Value |
|---|---|
| Hidden single attacks detected | 98.01 % |
| Single-flow attacks, right class | 99.65 % |
| Time-series attacks, right class | 91.91 % |
| False alarm rate | 0.34 % |
| Live time per flow | 248 µs (≈ 4,059 flows/s, 1 thread) |
| RAM | ≈ 206 MB |

Runner-up: XGBoost BAL_MS (fewer false alarms 0.22 %, but 10× slower per flow and 2× RAM).

### Phase 2: CIC-IDS2017 as an unseen test set
* **Problem:** Java CICFlowMeter 4.0 counts **payload** length; TRUST Lab counts the **full frame**.
  **Decision (user, option A):** use the Python cicflowmeter, which matches TRUST Lab.
* **Decision (user):** no retraining, CIC-IDS2017 is test-only.
* **Result** (`cicids_week_eval_20261031_222731`, Wednesday):

| Detector | Detection | False alarms |
|---|---|---|
| BAL_MS (TRUST Lab) | 0.13 % | 5.04 % |
| FLAT LightGBM | 4.87 % | 10.07 % |
| Suricata ALL alerts | 91.15 % | 12.76 % |
| Suricata THREATS | 0.00 % | 0.08 % |

* **Why it failed:** same names, different attacks (TRUST Lab DoS = UDP flood; CIC DoS = HTTP/TCP),
  different network and era (2017 office PCs vs 2025 IoT), TRUST Lab has no real time order and random IPs.
* **Decision:** stop using TRUST Lab/CIC-IDS2017 as the basis. Wrote dataset requirements: pcaps,
  one feature tool, IoT devices, real time order.

### Phase 3: New training data, CICIoT2023
* 105 real IoT devices, 33 attacks, 2023, pcaps + CSVs. Downloaded from the public Hugging Face copy
  (server has CLI only, the official site needs a form). 309/309 files, 8.9 GB, SHA-verified.
* 34 classes mapped to 8 categories: Normal, Flood DoS/DDoS, Slow DoS, Scan/Recon, Brute force,
  Web attack, C2/Bot, Spoofing/MITM.
* **Result** (`train_ciciot2023_20261102_141609`, 385,736 test rows):

| Model | Detection | False alarms | Category macro F1 | µs/row |
|---|---|---|---|---|
| FLAT | 94.2 % | 8.7 % | 0.653 | 231 |
| **BAL_MS** | **97.8 %** | **2.3 %** | 0.778 | 69 |
| SW_W32 | 97.3 % | 3.3 % | 0.788 | 68 |

Leak check clean (best single feature F1 only 0.30).

### Phase 4: Edge-IIoTset with Suricata inline (unseen network)
* Different lab and devices; 24 pcaps (14 attack, 10 normal sensors).
* 39 features rebuilt from pcaps **exactly like CIC's own script** (10 packets per row).
* **Problem:** Suricata failed with autofp on 128 cores (stream memory). **Fix:** single run-mode + memcaps + fail check.
* **Problem:** without calibration BAL_MS flagged **100 % of normal traffic**
  (`edge_inline_eval_20261104_151346`). Cause: Edge sensors send tiny packets (avg 58 bytes vs 267 in
  CICIoT2023) → everything looked like "Spoofing/MITM".

### Phase 5: Site calibration + autoencoder
* **Decision:** train attack knowledge once; every site **learns its own normal** after install
  (first 30 % of each normal pcap, no attack labels needed).
* Calibration = re-fit LightGBM on CICIoT2023 + local normal (with CICIoT2023 attacks mixed into local
  normal streams) + **autoencoder** on local normal only (threshold = 99.5 % of held-out normal error).
* **Problem:** first calibration dropped false alarms to 0.17 % but BAL_MS_cal detection fell to 18 %.
  **Fix:** mix attacks into local streams; add a mixed test (attacks hidden inside sensor traffic).
* **Result** (mixed test, `edge_inline_eval_20261104_164043`):

| Model | Detection | False alarms | Hidden attacks |
|---|---|---|---|
| BAL_MS (no calibration) | 99.98 % | **100 %** | 99.9 % |
| BAL_MS_cal | 54.5 % | 0.15 % | 74.8 % |
| **FLAT_cal** | 87.3 % | 0.15 % | 86.1 % |
| **Autoencoder** | **100 %** | 0.87 % | **100 %** |
| **FLAT_cal + AE** | **100 %** | 0.87 % | **100 %** |

* **Decision:** on IoT sensors FLAT_cal beats BAL_MS_cal (regular sensor windows look like regular
  floods) → **FLAT_cal is the gateway model**.

### Phase 6: Quarantine rule tuning

| Rule version | Normal wrongly blocked | Run |
|---|---|---|
| ML alone, 1 row, 600 s | 13.2 % | `…_160130` |
| ML + AE agree, 3 rows / 10 s, 300 s | 1.7 % | `…_161807` |
| **ML + AE agree, 2 rows / 10 s, 60 s** | **0.5 %** | `…_164043` (sweep of 25 settings) |

* **Final pipeline result:** attack packets that reached the resource: **0.00 %**
  (Suricata blocked 1.7 %, quarantined ≈ 32 %, alerted only ≈ 66 %). First block after ≈ 0.3 s.
* **Limit:** spoofed floods (random source IPs) have no single source to quarantine → need rate limiting.

---

## 5. Final detection architecture

```
IoT Client ── SPA knock (ML-KEM) → FIDO2 login → WireGuard ──┐
                                                             ▼
SDP GATEWAY:  ① Suricata inline (drop known attacks at first packet)
              ② Features: 10 packets = 1 row, 39 CICIoT2023 features
              ③ ML FLAT_cal (LightGBM) → P(attack)
              ⑥ Quarantine table (drop packets of a quarantined source)
                     │ features + score + alerts         ▲ QUARANTINE (IP, 60 s)
                     ▼                                   │
SDP CONTROLLER: ⓪ Site calibration (learn local normal at install)
                ④ Autoencoder → anomaly yes/no
                ⑤ Trust scorer + policy:
                   one detector flags                     → ALERT (lower trust)
                   ML P ≥ 0.9 AND AE anomaly, ≥ 2 rows /10 s → QUARANTINE 60 s
                     ▼
              Protected resource (allowed traffic only)
```

Why each piece: Suricata blocks known attacks at once and names them; ML works on encrypted traffic
and is fast; the autoencoder catches unknown/hidden attacks; requiring ML + AE + repeated evidence
keeps false blocks low. Full benefits/demerits: `HANDOVER_NETWORK_THREAT_DETECTION.md` section 4.

---

## 6. Trust score engine study (latest session)

The questions asked, in order, and what we found in the code (`SDP_CONTROLLER/trust_scorer.py`,
`detection/suricata_signal.py`, `detection/ml_signal.py`, `ml/generate_dataset.py`, `scenarios.yaml`,
`policies.yaml`, `README.md`).

### 6.1 Q1: What telemetry does the Controller use for the trust score?

Three sources, added into one score from 0 to 100:

| Source | Max points | Comes from |
|---|---|---|
| Device posture | 60 | `device.signals` in the access request (6 yes/no checks) |
| Suricata IDS alerts | 25 | `eve.json` → `detection/suricata_signal.py` → `telemetry_snapshot.json` |
| ML flow classifier | 15 | flow JSON → RandomForest `ml/model.joblib` → `telemetry_snapshot.json` |

Data flow:
```
eve.json ──► suricata_signal.py ─┐
                                 ├─► run_pipeline.py ─► telemetry_snapshot.json (per IP)
flows.json ─► ml_signal.py ──────┘                              │
                                                                ▼
access request (user, device.signals, resource, context.ip) ─► enrich_request()
                                                                │
                        device.trust_score + device.trust_breakdown
                                                                ▼
                                    policies.yaml ─► ALLOW / DENY / MFA
```

### 6.2 Q2: Full list of inputs the engine needs

**A. Request fields**

| # | Field | Type | Meaning | Use |
|---|---|---|---|---|
| A1 | `context.ip` | string | IP of the device asking for access | Key to find the device in `telemetry_snapshot.json` |
| A2 | `device.trust_score` | number, optional | Score set directly in the request (test override) | If present, **no calculation is done**, this value is used |
| A3 | `device.signals` | dict | Holds the posture signals (B) and fallback flags (C) | Read by the posture score and fallback logic |

**B. Device posture signals (60 points).** Each is a boolean. It gets its points **only if exactly
`True`**. False, missing or anything else = 0 (unknown = untrusted).

| # | Signal | Points | Meaning |
|---|---|---|---|
| B1 | `device_managed` | 15 | Device is enrolled in company device management (MDM) |
| B2 | `os_patched` | 15 | OS has the latest security updates. **No rule in code defines "patched"**; the client sends `os_patch_days` but nothing converts it yet |
| B3 | `known_device` | 10 | Device was seen/registered before |
| B4 | `location_expected` | 10 | Request comes from a usual place for this user |
| B5 | `disk_encrypted` | 5 | Full-disk encryption on |
| B6 | `antivirus_running` | 5 | Antivirus / endpoint protection active |

**C. Fallback flags** (used **only if the IP is not in the telemetry snapshot**)

| # | Signal | True | False | Missing |
|---|---|---|---|---|
| C1 | `no_suricata_alerts` | as 0 alerts → 25 pts | as 3 high alerts → 2 pts | half credit → 12 pts |
| C2 | `ml_anomaly_score_ok` | as rate 0 → 15 pts | as rate 0.9, port_scan → 2 pts | half credit → 7 pts |

**D. Suricata telemetry (25 points)**

Read from each `eve.json` line:

| # | Field | Meaning |
|---|---|---|
| D1 | `event_type` | Only `"alert"` lines are counted |
| D2 | `src_ip` | Alerts are grouped by source IP (presumed attacker) |
| D3 | `alert.severity` | 1 = critical, 2 = high, 3 = medium (missing → 3) |
| D4 | `alert.category` | e.g. "A Network Trojan was Detected" (display only) |
| D5 | `alert.signature` | e.g. "ET MALWARE Cobalt Strike Beacon" (display only) |

Summary per device used in the score:

| # | Field | Score rule |
|---|---|---|
| D6 | `alert_count` | 0 alerts → **25** |
| D7 | `max_severity` | any critical (1) → **0**; high (2) → max(0, 8 − 2 × count); medium (3) only → max(0, 25 − 3 × count) |

If the IP is in the snapshot but has no Suricata entry → treated as 0 alerts (25 points).

**E. ML telemetry (15 points)**

The 15 features the RandomForest reads per flow (CIC-IDS2017 style):

| # | Feature | Meaning |
|---|---|---|
| E1 | `flow_duration` | How long the flow lasted (ms) |
| E2 | `total_fwd_packets` | Packets client → server |
| E3 | `total_bwd_packets` | Packets server → client |
| E4 | `total_fwd_bytes` | Bytes client → server |
| E5 | `total_bwd_bytes` | Bytes server → client |
| E6 | `fwd_packet_len_mean` | Average client packet size (E4 ÷ E2) |
| E7 | `bwd_packet_len_mean` | Average server packet size (E5 ÷ E3) |
| E8 | `flow_bytes_per_sec` | Bytes per second, both directions |
| E9 | `flow_packets_per_sec` | Packets per second, both directions |
| E10 | `fwd_iat_mean` | Average time gap between client packets (ms) |
| E11 | `bwd_iat_mean` | Average time gap between server packets (ms) |
| E12 | `syn_flag_count` | TCP SYN count (high → scan / SYN flood) |
| E13 | `fin_flag_count` | TCP FIN count (normal close) |
| E14 | `rst_flag_count` | TCP RST count (high → scan) |
| E15 | `dst_port` | Destination port (many attacks target specific ports) |

Missing feature → 0.0. Output per flow: `benign`, `port_scan`, `dos`, `brute_force` or `c2_beacon`.

Summary per device used in the score:

| # | Field | Meaning | Score rule |
|---|---|---|---|
| E16 | `flow_count` | Flows scored for this IP | used for E18 |
| E17 | `malicious_flows` | Flows not called benign | used for E18 |
| E18 | `anomaly_rate` | E17 ÷ E16 (0..1) | points = round(15 × (1 − rate)) |
| E19 | `top_class` | Most common attack class | `c2_beacon` or `dos` → **−5 more** (floor 0) |

If the IP is in the snapshot but has no ML entry → rate 0, benign (15 points).

**Final formula**
```
trust_score = posture (B1..B6, 0-60) + suricata (D6, D7, 0-25) + ml (E18, E19, 0-15)   → capped at 100
```

**Policy thresholds** (`policies.yaml`): score < 40 → hard DENY; public/internal access needs ≥ 50;
contractor public access ≥ 60; confidential and admin access ≥ 70.

**Count:** 12 direct inputs (6 posture + 2 Suricata + 2 ML + 2 fallback) + the IP for lookup.
Underneath: 5 fields per `eve.json` line and 15 features per flow.

**Demo example (README, scenario "Bob"):** posture 45 (unpatched laptop), Suricata 25, ML 15 = **85 → ALLOW + MFA**.
With attack telemetry (Cobalt Strike critical alert, 4/4 flows malicious): 45 + 0 + 0 = **45 → DENY**
(confidential needs ≥ 70). Policy file did not change; only the live telemetry did.

### 6.3 Q3: Is the trust score engine arithmetic or an ML model?

**Arithmetic (rule-based).** It is a fixed weighted sum with hand-set weights. Nothing in the engine is
trained. The same inputs always give the same score, and the breakdown explains every point.

The only ML is **inside one input**: the RandomForest that labels flows. So the system is a **hybrid**:
an arithmetic scoring engine that takes an ML detector's output as one of its inputs.

| Part | Type |
|---|---|
| Trust score fusion (`trust_scorer.py`) | Arithmetic, fixed weights |
| Suricata signal | Rules (signatures) → arithmetic |
| ML signal (`ml/model.joblib`) | ML (RandomForest) → arithmetic |
| Policy decision (`policies.yaml`) | Rules (thresholds) |

Report wording: **"weighted additive trust model fusing posture, IDS and ML evidence"**.

### 6.4 Q4: How were the numbers decided?

**By hand. No method or source is written anywhere** (code, README, CHECKLIST, reports were checked).
The README states the rules but never the reason. Probable reasoning (**my reading, not documented**):

| Number | Probable reason |
|---|---|
| 60 / 25 / 15 split | Posture is checked at every login → biggest; Suricata is precise (few false alarms) → more than ML; ML is trained on synthetic data → least |
| Managed 15, Patched 15 | Unmanaged or unpatched device = biggest risk |
| Known 10, Location 10 | Medium: "usual device, usual place" |
| Encrypted 5, Antivirus 5 | Low: protect data at rest, say little about live infection |
| Critical alert → 0 | A critical alert (e.g. Cobalt Strike) should remove all Suricata trust |
| 8 − 2·count, 25 − 3·count | Penalty grows with alert count; exact values have no stated reason |
| ML linear, −5 for C2/DoS | Simple linear penalty; extra cut for the most dangerous classes |
| Half credit if no telemetry | Middle ground: no data is not proof of good or bad |

The weights and thresholds (40/50/60/70) were clearly chosen **so the demo works** (Bob 85 → 45 crosses
the 70 line). They were **not tested on real traffic**. For the thesis these are **design assumptions**.

Ways to justify them:
1. **AHP (Analytic Hierarchy Process):** pair-wise expert comparison of the factors → computed weights (citable).
2. **Learn from data:** logistic regression on labelled sessions → coefficients become weights; report AUC / false alarms.
3. **Sensitivity analysis:** change each weight ±25 % and show which decisions flip.
4. **Use measured detector quality:** set Suricata/ML shares from their real precision and false-alarm rates in our runs.

### 6.5 Small issues found in the code (not fixed, only noted)
* `_suricata_score` comment says high severity = "4 pts", but the code gives 8 − 2 × count (1 alert = 6).
* Suricata alerts are grouped by **source IP only**; attacks seen as destination are not counted.
* Posture fields do not match: client sends `os_patch_days`, `antivirus_active`, `firewall_active`,
  `screen_lock`, `trust_anchor_*`, `vpn_active`; scorer expects `os_patched`, `antivirus_running`,
  `device_managed`, `known_device`, `location_expected`. `firewall_active`, `screen_lock` and the TPM
  trust anchor are **not used** in the score.
* `SDP_CLIENT/main.py:145`: posture is collected but **not sent** yet.
* `ml/model_report.txt` shows the RandomForest was trained on another machine (`/home/koppa/...`),
  on 5,000 **synthetic** flows (accuracy 0.970, macro F1 0.958).

---

## 7. Gap: detection work vs the trust scorer

The ML research (sections 4–5) and the Controller's trust scorer (section 6) are **not connected yet**.

| Topic | Trust scorer today | Research result (what it should use) |
|---|---|---|
| ML model | RandomForest, synthetic data, 15 features | LightGBM **FLAT_cal**, CICIoT2023 + site calibration, 39 features |
| Unknown attacks | not covered | **Autoencoder** at the Controller |
| Input data | canned JSON files in `data/` | live Gateway messages (1 row per 10 packets) |
| Suricata | offline `eve.json` | inline at Gateway (THREATS rules drop) |
| Action | ALLOW / DENY / MFA only | + **QUARANTINE** (ML P ≥ 0.9 AND AE, 2 rows / 10 s, 60 s) |
| Posture | static `scenarios.yaml` | real `PostureReport` from the client (not sent yet) |
| Weights | hand-set | not yet justified (section 6.4) |

This is CHECKLIST task **6.1** ("explain how each one feeds the trust score in `trust_scorer.py`").

---

## 8. All key decisions (one table)

| # | Problem / question | Decision | Why |
|---|---|---|---|
| 1 | Which env for training | `pqzta-venv` default; `cfm-py` only CFM; `gpu-env` only GPU tests | keep envs clean (user rule) |
| 2 | Single vs time-series attacks | Balanced multi-scale model (BAL_MS) | old models good at only one |
| 3 | LightGBM GPU crash | Train on CPU | GPU/OpenCL learner bug |
| 4 | Per-flow latency too high | Fast ring-buffer live builder | 8.2 ms → 0.25 ms |
| 5 | Bulk feature leak | Drop 6 bulk features | they encoded the tool version |
| 6 | Java vs Python CICFlowMeter | Python (option A, user) | matches TRUST Lab full-frame lengths |
| 7 | Retrain on CIC-IDS2017? | No, test-only (user) | fair unseen test |
| 8 | TRUST Lab does not transfer | Move to CICIoT2023 | real IoT, pcaps, 33 attacks |
| 9 | No form access on CLI server | Download from Hugging Face copy, verify SHA | server has CLI only |
| 10 | Test set | Edge-IIoTset (Kaggle archive) | different lab, pcaps, overlapping attacks |
| 11 | Suricata crash on 128 cores | single run-mode + memcaps | stream memory error |
| 12 | 100 % false alarms on new site | **Site calibration** (learn local normal) + autoencoder | normal traffic differs per site |
| 13 | Which gateway model | FLAT_cal (not BAL_MS_cal) | 87 % vs 54 % on IoT sensors |
| 14 | Quarantine too aggressive | ML + AE must agree, ≥ 2 rows in 10 s, 60 s | false block 13 % → 0.5 % |
| 15 | Where things run | Suricata + ML at Gateway; AE + trust + policy at Controller | fast local blocking, one baseline per site |
| 16 | Trust score engine type | Keep arithmetic (explainable), but justify weights | reviewers will ask "why 15?" |

---

## 9. Open items and next steps

1. **Connect detection to the trust scorer** (section 7, CHECKLIST 6.1): feed FLAT_cal + AE + inline Suricata, add QUARANTINE.
2. **Justify the trust weights** (AHP, learned weights, or sensitivity analysis).
3. **Send real posture** from the client and map its fields to the scorer.
4. **Own SDP testbed:** attacks from logged-in clients through WireGuard/SPA/FIDO2.
5. **Rate limiting** for spoofed floods (no single source to quarantine).
6. **Live speed test** of the whole gateway path.
7. **Drift handling:** retrain calibration/AE when normal traffic changes.
8. **Partial quarantine** (keep-alive + re-verification allowed).
9. CIC-IDS2017 Tue/Thu/Fri evaluation unfinished (old model; low priority now).
10. CHECKLIST 1C.6 (IoT budget rule), 2.3 (Suricata requirements doc), plan Stage 5 on TRUST Lab: open.

---

## 10. Files and runs index

| File | Purpose |
|---|---|
| `CLAUDE.md`, `CHECKLIST.md` | Rules, file list, change log; task list |
| `MODELS/results/BEST_MODEL.md` | Phase 1 decision (TRUST Lab BAL_MS) |
| `MODELS/results/HANDOVER_NETWORK_THREAT_DETECTION.md` | Detailed handover of detection part |
| `MODELS/results/PROJECT_PROGRESS_REPORT.md` | This document |
| `MODELS/MODEL SW_XGBOOST/*.py` | Phase 1 (window trade-off, balanced, live latency) |
| `MODELS/common/live_windows.py` | Fast live feature builder |
| `MODELS/Suricata/*.py` | Phase 2 (CIC-IDS2017 flows + week evaluation) |
| `MODELS/data/*.py` | Dataset download + SHA check (CICIoT2023, Edge-IIoTset) |
| `MODELS/MODEL CICIOT2023/train_ciciot2023.py` | CICIoT2023 training |
| `MODELS/MODEL CICIOT2023/site_calibration.py` | Site calibration + autoencoder |
| `MODELS/MODEL CICIOT2023/edge_inline_eval.py` | Full pipeline test on Edge-IIoTset |
| `SDP_CONTROLLER/trust_scorer.py` | Trust score engine |
| `SDP_CONTROLLER/detection/*.py` | Suricata + ML signal extractors |
| `SDP_CONTROLLER/policies.yaml`, `scenarios.yaml` | Policy rules, demo requests |

Key runs (`runs/`): `gpu_check_20261030_205158`, `sw_lgbm_balanced_nobulk_20261031_121031`,
`live_latency_20261031_122954`, `cicids_week_eval_20261031_222731`, `train_ciciot2023_20261102_141609`,
`edge_inline_eval_20261104_151346` (no calibration), `edge_inline_eval_20261104_164043` (final).

---

## 11. How to run (PC 2)

```bash
source /home/abhinav_iot/pqzta-venv/bin/activate
cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA

# CICIoT2023 training
python "MODELS/MODEL CICIOT2023/train_ciciot2023.py" --models FLAT BAL_MS SW_W8 SW_W32 SW_W56

# Full pipeline on Edge-IIoTset (calibration + quarantine sweep)
python "MODELS/MODEL CICIOT2023/edge_inline_eval.py" --pipeline-model FLAT_cal
```

Trust score demo (SDP_CONTROLLER; needs `rich`, `joblib`, `scikit-learn`, `pyyaml`; see `SDP_CONTROLLER/requirements.txt`):
```bash
cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA/SDP_CONTROLLER
python demo.py                    # baseline
python run_pipeline.py --attack   # attack telemetry → Bob flips to DENY
python demo.py
python run_pipeline.py --benign   # restore
```
