# Handover: Network Threat Detection (Quantum Secure Zero Trust Architecture for IoT)

Final year project. This file explains **what the threat detection part does, why it looks like this,
how we got here, and how to run it**. All numbers come from real runs on PC 2 (folder names given, all in
`runs/`). Last update: 2026-11-04.

---

## 1. Summary

| | |
|---|---|
| **Goal** | Detect attacks in traffic between Client ↔ Controller and Client ↔ Resource, and stop them **before they reach the protected resource**. Traffic: HTTP, HTTPS, TCP, UDP, SYN/ACK, ... Output: attack yes/no + category. |
| **Final design** | **Gateway:** Suricata (inline) + ML model (LightGBM `FLAT_cal`). **Controller:** Autoencoder + trust scorer + policy. **Gateway** enforces the quarantine. |
| **Training data** | CICIoT2023 (attack knowledge) + the site's own normal traffic (learned at install, no attack labels). |
| **Test data** | Edge-IIoTset (a different IoT lab, never used for training). |
| **Result (Edge-IIoTset)** | **0 % of attack packets reached the resource**; hidden attacks detected **100 %** (ML + AE); normal traffic wrongly blocked **≈ 0.5 %** (recommended setting) |
| **Main lesson** | A model trained on one network does **not** know another network's normal traffic. Every site must **learn its own normal** first (site calibration). |

---

## 2. Final architecture

```
┌─────────────┐
│ IoT Client  │  SPA knock (ML-KEM) → FIDO2 login → WireGuard tunnel
└──────┬──────┘
       ▼
┌──────────────────────────────── SDP GATEWAY ────────────────────────────────┐
│ ① PREVENT   Suricata (inline IPS, ET Open rules)                            │
│             known attack ──► DROP the connection (first packet)             │
│                  │ allowed packets                                          │
│ ② FEATURES  1 row = 10 packets, 39 CICIoT2023 features                      │
│ ③ DETECT    ML model FLAT_cal (LightGBM) → P(attack) + category guess       │
│ ⑥ ENFORCE   Quarantine table: drop packets of a quarantined source          │
│             (close pinhole / revoke WireGuard session)                      │
└────────┬───────────────────────────────────────────────▲────────────────────┘
         │ source IP, 39 features, ML score, alerts       │ QUARANTINE (IP, 60 s)
         ▼                                                │
┌──────────────────────────────── SDP CONTROLLER ─────────┴───────────────────┐
│ ⓪ LEARN     Site calibration at install (local normal, no attack labels)    │
│ ④ CONFIRM   Autoencoder (site's normal baseline) → anomaly yes/no           │
│ ⑤ DECIDE    Trust scorer + policy                                           │
│             • one detector flags                    → ALERT (lower trust)    │
│             • ML P ≥ 0.9 AND AE anomaly, ≥ 2–3 rows                          │
│               from the same source within 10 s      → QUARANTINE 60 s        │
└─────────────────────────────────────────────────────────────────────────────┘
         ▼ allowed traffic only
   Protected resource
```

| Step | Where | Component | Detects? | Blocks? |
|---|---|---|---|---|
| ⓪ | Controller | Site calibration | – | – |
| ① | Gateway | **Suricata** | ✅ known signatures | ✅ the connection, at once |
| ③ | Gateway | **ML (FLAT_cal)** | ✅ attack + category guess | ❌ (votes for quarantine) |
| ④ | Controller | **Autoencoder** | ✅ anything unlike the site's normal | ❌ (confirms quarantine) |
| ⑤ | Controller | Trust scorer + policy | – | decides |
| ⑥ | Gateway | **Quarantine** | – | ✅ the whole source for 60 s |

**Quarantine** = the source IP is cut off for a fixed time; other devices keep working. In the tests all its
packets are dropped (full quarantine). Recommended for the real system: **partial quarantine**: block the
resource, but allow rate-limited WireGuard keep-alive and re-verification to the Controller (full quarantine
only for floods / repeat offenders).

---

## 3. The journey: where we started and why we changed

### Phase 1: TRUST Lab dataset (2025, UPCT)
* **What:** 16 classes (Benign + 15 attacks), CICFlowMeter flow features (70, later 64).
* **Models tried:** XGBoost, LightGBM, sliding-window (SW) XGBoost/LightGBM (windows 8…64), LSTM, and
  "balanced" models.
* **Window study** (`sw_xgb_window_tradeoff_20261030_231549`, `sw_lgbm_window_tradeoff_20261031_004422`):
  a bigger window gives fewer false alarms and better time-series attacks, but **hidden single attacks drop
  from 99.7 % to ≈ 91 %**.
* **Chosen model: LightGBM BAL_MS** (Balanced Multi-Scale = current flow + window 8 + window 56 + deviation,
  trained with solo attacks). Run `sw_lgbm_balanced_nobulk_20261031_121031`: hidden attacks 98.0 %,
  single attacks right class 99.65 %, time-series right class 91.9 %, false alarms 0.34 %, 248 µs/flow,
  ≈ 4,000 flows/s on 1 thread, ≈ 206 MB.
* **Data leak found:** 6 "bulk" features were always 0 in some classes (two CICFlowMeter versions) → removed.
* **Problems found with TRUST Lab:** one file per class (no real time order), randomised IPs, DoS and Slowloris
  are **UDP only**, no pcaps, two tool versions.

### Phase 2: CIC-IDS2017 as a test (Wednesday)
* Run `cicids_week_eval_20261031_222731`: **BAL_MS caught 0.13 %** of attacks (false alarms 5 %); FLAT 4.9 %;
  Suricata (all alerts) 91 % but 12.8 % false alarms; Suricata threat rules 0 %.
* **Why it failed:** same names, different attacks (TRUST Lab DoS = UDP flood; CIC DoS = HTTP over TCP),
  different network and era (2017 office PCs vs 2025 IoT), and the window mixed traffic of all hosts.
* **Decision:** CIC-IDS2017 is not an IoT dataset → not a good basis. We wrote dataset requirements:
  pcaps, one feature tool, IoT devices, many protocols per attack, real time order.

### Phase 3: New training dataset, CICIoT2023
* **Why:** 105 real IoT devices, 33 attacks (SYN/ACK/UDP/ICMP/HTTP floods, slowloris, scans, brute force,
  web attacks, spoofing, Mirai), pcaps + CSVs, 2023.
* Downloaded from the public Hugging Face copy (CLI only): 309 per-class CSVs, 8.9 GB.
* 34 classes mapped to our categories (Normal + 7): Flood DoS/DDoS, Slow DoS, Scan/Recon, Brute force,
  Web attack, C2/Bot, Spoofing/MITM. Not in CICIoT2023: Exploit, Exfiltration, DNS abuse, TLS, Evasion.
* TRUST Lab could **not** be merged (different features, no pcaps).
* Run `train_ciciot2023_20261102_141609` (test stream, 385,736 rows):

| Model | Detection | False alarms | Category macro F1 | Hidden attacks | µs/row |
|---|---|---|---|---|---|
| FLAT | 94.2 % | 8.7 % | 0.653 | 95.7 % | 231 |
| **BAL_MS** | **97.8 %** | **2.3 %** | 0.778 | 91.5 % | 69 |
| SW_W32 | 97.3 % | 3.3 % | 0.788 | 91.5 % | 68 |

  Leak check clean (best single feature F1 0.30). The window trade-off from TRUST Lab was confirmed.

### Phase 4: Test on Edge-IIoTset with Suricata inline (unseen network)
* **Why Edge-IIoTset:** different lab and devices, has pcaps, attacks overlap with CICIoT2023.
  24 pcaps (14 attack, 10 normal sensors), from the public Kaggle copy.
* The 39 features were rebuilt from pcaps **exactly like CIC's own script** (`pcap2csv/Feature_extraction.py`).
* Suricata first failed (autofp on 128 cores → memory error) → fixed (1 thread, more memory).
* **Result without calibration** (`edge_inline_eval_20261104_151346`): BAL_MS flagged **100 % of normal
  traffic**. Feature-shift check: Edge sensors send tiny packets (avg 58 bytes vs 267 in CICIoT2023 Benign;
  min 54 vs 66) → the model called every sensor "Spoofing / MITM".

### Phase 5: Site calibration + Autoencoder (the enterprise approach)
* **Idea:** train the attack knowledge once; each site **learns its own normal** after install.
  First 30 % (by time) of every normal pcap = learning period; test = the rest + all attacks.
* Calibration re-fits LightGBM on CICIoT2023 + local normal (with CICIoT2023 attacks mixed **into** the local
  normal) and trains an **autoencoder on local normal only** (threshold = 99.5 % of held-out normal error).
* **Mixed test** (Edge attacks hidden inside normal sensor traffic), run `edge_inline_eval_20261104_164043`:

| Model | Detection | False alarms | Hidden attacks | Attack start | Right category |
|---|---|---|---|---|---|
| BAL_MS (no calibration) | 99.98 % | **100 %** | 99.9 % | 99.9 % | 21 % |
| BAL_MS_cal | 54.5 % | 0.15 % | 74.8 % | 67.5 % | 8 % |
| **FLAT_cal** | 87.3 % | 0.15 % | 86.1 % | 78.0 % | 5 % |
| **Autoencoder** | **100 %** | 0.87 % | **100 %** | **100 %** | – |
| **FLAT_cal + AE** | **100 %** | 0.87 % | **100 %** | **100 %** | 5 % |

* On IoT sensors, **FLAT_cal beats BAL_MS_cal** (sensor windows are very regular, floods too) → FLAT_cal is
  the pipeline model.

### Phase 6: Quarantine rule tuning
| Version | Normal (sensor) wrongly blocked | Note |
|---|---|---|
| ML alone, 1 row, 600 s | 13.2 % | one false row blocked a sensor for 10 min |
| ML + AE agree, 3 rows / 10 s, 300 s | 1.7 % | run `edge_inline_eval_20261104_161807` |
| **ML + AE agree, 2 rows / 10 s, 60 s** | **0.5 %** | best in the sweep (run `…_164043`) |

Sweep (25 settings, charts `02_quarantine_heatmaps.png`, `03_quarantine_tradeoff.png`,
`04_quarantine_reaction_speed.png`): quarantine **time** drives false blocking; **min hits** costs speed and
coverage (attack packets before first block 19k at 1–2 hits → 59k at 8; never-blocked attacks 0 → 4).
Attack blocked stays ≈ 34 % in every setting (see demerits: spoofed floods).

**Final pipeline result** (Edge-IIoTset, 3 hits/300 s run): attack packets **reached 0.00 %**: blocked by
Suricata 1.7 %, quarantined by ML+AE ≈ 32 %, alerted only ≈ 66 %. First block after ≈ 0.3–0.4 s (median).

---

## 4. Why each component: benefits and demerits

### 4.1 Suricata (inline, at the Gateway)
| Benefits | Demerits |
|---|---|
| Blocks **known** attacks at the **first packet**, before any harm | Only knows attacks that have a rule (Edge: threat rules caught 1.7 % of attack packets) |
| Names the attack (signature) → explainable | Cannot read **encrypted** traffic (HTTPS, WireGuard inside) |
| No training, rules update daily (ET Open) | Engine/policy alerts are noisy (CIC: 12.8 % false alarms with all alerts) → only threat rules used for blocking |
| Independent of the site's normal traffic | ≈ 500–900 MB RAM per instance; needs tuning (failed with 128 threads) |

### 4.2 ML model FLAT_cal (LightGBM, at the Gateway)
| Benefits | Demerits |
|---|---|
| Fast: ≈ 70–230 µs per row (10 packets), small model (a few MB) | Needs **calibration per site** (without it: 100 % false alarms on Edge) |
| Works on encrypted traffic (uses sizes, flags, timing, not payload) | **Category does not transfer** to a new network (≈ 5 % right) → ML says "attack", Suricata names it |
| Brings attack knowledge from CICIoT2023 (floods, scans, brute force, web) | Only 7 of our 12 categories in the training data |
| After calibration: 0.15 % false alarms, 87 % detection (mixed test) | A row exists only after 10 packets → cannot stop the very first packet |

Why FLAT and not BAL_MS here: BAL_MS (windows) was best on TRUST Lab and CICIoT2023, but on the IoT sensor
site its calibrated version found only 54 % (regular sensor windows look like regular floods). FLAT_cal: 87 %.

### 4.3 Autoencoder (at the Controller)
| Benefits | Demerits |
|---|---|
| Learns **only normal** → catches **unknown and hidden** attacks (100 % in the mixed test) | Gives **no category** ("unusual", not "DDoS") |
| No attack labels needed; trains in seconds (GPU) | 0.87 % false alarms; must be retrained when normal traffic changes (drift) |
| One baseline per site at the Controller, shared by all Gateways | Its 100 % is partly easy on Edge-IIoTset (attackers are separate hosts) → must be re-tested on our own SDP testbed |

### 4.4 Placement: Suricata + ML at Gateway, Autoencoder at Controller
| Benefits | Demerits |
|---|---|
| Fast local blocking of known attacks (no round trip) | Quarantine waits for one Gateway → Controller → Gateway round trip (few ms on LAN; not in the test numbers) |
| Controller already owns trust score + policy → quarantine is a normal policy action | Gateway must send one small message per 10 packets (≈ 39 numbers; can be batched) |
| One autoencoder baseline for many Gateways; easy retraining in one place | If the Controller is down: no quarantine → fallback needed (Gateway rate-limits on very high ML scores) |

### 4.5 Quarantine rule (ML + AE agree, repeated, per source, 60 s)
| Benefits | Demerits |
|---|---|
| Two detectors + repeated evidence → few false blocks (0.5 %) | **Spoofed floods** (random source IPs) have no single source to block → ≈ 66 % of attack packets were only alerted; need **rate limiting** |
| Stops floods, scans, brute force, web attacks from one source in ≈ 0.3 s | Single short attacks (1–5 rows) are alerted, not blocked |
| Short time (60 s) limits damage from a wrong block | Full quarantine also drops keep-alives → sessions reconnect afterwards (use partial quarantine) |

---

## 5. Limitations and future work
1. **Own SDP testbed** (most important): attacks from normal-looking, logged-in clients; real WireGuard,
   SPA, FIDO2 traffic. Edge-IIoTset attackers were separate hosts.
2. **Rate limiting** for spoofed floods (per destination / per protocol), not per source IP.
3. **Live speed test** of the whole Gateway path (features + ML + messaging), not only the model.
4. **Drift handling:** retrain the autoencoder / calibration automatically when normal traffic changes.
5. **Categories:** take the name from Suricata, or add a small labelled set from our own testbed.
6. **Partial quarantine** in the Gateway/Controller code (keep-alive + re-verification allowed).
7. Labels: 2 Edge attack pcaps (DDoS UDP, MITM) could not be matched to their CSV by IP pair → whole file
   counted as attack.
8. CIC-IDS2017 Tuesday/Thursday/Friday evaluation was not finished (old TRUST Lab model).

---

## 6. Files

| File | Purpose |
|---|---|
| `MODELS/data/download_ciciot2023_csv.py` | Download CICIoT2023 CSVs (`--hf`, no form) |
| `MODELS/data/verify_ciciot2023_sha.py` | Check the download against Hugging Face hashes (path must be adapted: data now in `CSV/<class>/`) |
| `MODELS/data/download_edgeiiotset.py` | Download Edge-IIoTset (Kaggle archive, no login), unpack pcaps |
| `MODELS/MODEL CICIOT2023/train_ciciot2023.py` | Train FLAT / BAL_MS / SW on CICIoT2023 (attack + category) |
| `MODELS/MODEL CICIOT2023/site_calibration.py` | Site calibration: re-fit with local normal + autoencoder |
| `MODELS/MODEL CICIOT2023/edge_inline_eval.py` | Full pipeline test on Edge-IIoTset (Suricata inline + ML + AE + quarantine, mixed test, sweep, charts) |
| `MODELS/results/BEST_MODEL.md` | Phase 1 decision (TRUST Lab BAL_MS) |
| `MODELS/MODEL SW_XGBOOST/*.py`, `MODELS/Suricata/*.py` | Phase 1–2 scripts (TRUST Lab, CIC-IDS2017) |
| `CLAUDE.md`, `CHECKLIST.md` | Project rules, file list, change log, task list |

Key runs (in `runs/`): `sw_lgbm_balanced_nobulk_20261031_121031` (Phase 1),
`cicids_week_eval_20261031_222731` (Phase 2), `train_ciciot2023_20261102_141609` (Phase 3),
`edge_inline_eval_20261104_151346` (Phase 4), `edge_inline_eval_20261104_164043` (Phase 5–6, final).

Data: `DataSet/CICIoT2023_csv/CSV/<class>/*.csv`, `DataSet/Edge-IIoTset/` (+ `_kaggle_archive.zip`, has the
label CSVs, keep it).

---

## 7. How to run (PC 2)

Environment: **pqzta-venv** (pandas, LightGBM, PyTorch, matplotlib). Suricata 8 installed on the system.

```bash
source /home/abhinav_iot/pqzta-venv/bin/activate
cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA

# 1) train on CICIoT2023 (≈ 6 min)
python "MODELS/MODEL CICIOT2023/train_ciciot2023.py" --models FLAT BAL_MS SW_W8 SW_W32 SW_W56

# 2) full pipeline on Edge-IIoTset with calibration + sweep (≈ 8 min)
python "MODELS/MODEL CICIOT2023/edge_inline_eval.py" --pipeline-model FLAT_cal

# 3) only redraw the sweep charts of an earlier run
python "MODELS/MODEL CICIOT2023/edge_inline_eval.py" --replot runs/edge_inline_eval_<timestamp>
```

Each run writes `runs/<script>_<timestamp>/` with `run.log`, `config.json`, `results.json`, `REPORT.md`, charts.

Main settings (top of `edge_inline_eval.py`): `CALIBRATE_SHARE = 0.30`, `ALERT_P = 0.5`, `QUARANTINE_P = 0.9`,
`QUARANTINE_NEEDS_AE = True`, `QUARANTINE_MIN_HITS = 3`, `QUARANTINE_S = 300`
(**recommended: 2 hits, 60 s**, from the sweep).
