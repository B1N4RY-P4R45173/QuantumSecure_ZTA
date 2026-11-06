# Project CHECKLIST — ML / IDS threat detection for the Zero Trust IoT system

Legend: `[x]` done · `[~]` partly done · `[ ]` not started
Status was checked against the existing files on 2026-10-30 (second check: same day, file by file). "Evidence" shows where the result is saved.

Goal: find the best threat detector for an **IoT edge device**.
- **Known attacks:** a sliding-window (SW) ML model vs Suricata.
- **Unknown attacks:** an autoencoder trained only on normal traffic.
- On an IoT device, **detection quality must be traded off against RAM and speed**.

---

## Phase 0 — Environment setup (PC 2)

- [x] 0.1 Check that the GPUs work with torch. Evidence: `runs/gpu_check_20261030_205158/` (2× A2, CUDA OK)
- [x] 0.2 Write down the packages in each venv (CLAUDE.md section 5)
- [ ] 0.3 Install `lightgbm` and `matplotlib` into `pqzta-venv` (needed by SW_LIGHTGBM and charts)
- [ ] 0.4 Install `torch` (CUDA 12.8 build) into `pqzta-venv`, for the LSTM and autoencoder.
      Env roles: `pqzta-venv` = all training · `cfm-py` = only CICFlowMeter · `gpu-env` = only GPU tests
- [ ] 0.5 Make a quick test run of every training script (`run_all.sh --quick`) on PC 2

---

## Phase 1 — Known attacks on TRUST Lab: train, score, pick the best model

### 1A. Baseline models (one flow, no time)
- [x] 1A.1 Preprocess TRUST Lab (time-ordered split: train / validation / test). `MODELS/preprocess.py`
- [x] 1A.2 Train XGBoost. Evidence: `MODELS/MODEL XGBOOST/output/`
- [x] 1A.3 Train LightGBM. Evidence: `MODELS/MODEL LIGHTGBM/output/`
- [x] 1A.4 Train LSTM (sequence of the last 32 flows). Evidence: `MODELS/MODEL LSTM/output/`

### 1B. Time-series models (sliding window)
- [x] 1B.1 SW_XGBoost with window 32. Evidence: `MODELS/results/SW_XGBOOST.json`
- [x] 1B.2 SW_LightGBM with window 32. Evidence: `MODELS/results/SW_LIGHTGBM.json`
- [x] 1B.3 Compare all 5 models (F1, detection, false alarms, per class, speed, RAM). Evidence: `MODELS/results/COMPARISON.md`

### 1C. Optimal window size (performance vs RAM trade-off)
- [x] 1C.1 SW_XGBoost window sweep: 4, 8, 16, 32, 64, 128. Evidence: `MODELS/results/WINDOW_SWEEP.md` (best on validation = 64)
- [x] 1C.2 SW_XGBoost two windows (8+64) vs single windows. Evidence: `MODELS/results/WINDOW_COMPARISON.md`
- [x] 1C.3 **SW_LightGBM window sweep** with the same windows and the same test rows as 1C.1
      Evidence: `runs/sw_lgbm_window_tradeoff_20261031_004422/` (8..64, step 8, FINISHED OK)
- [x] 1C.4 For every window, measure for both models:
      F1, macro F1, false alarm rate, **peak RAM (MB)**, **model size on disk**, **latency per flow (ms)**, flows/s
      (XGB: `runs/sw_xgb_window_tradeoff_20261030_231549/`, LGBM: `runs/sw_lgbm_window_tradeoff_20261031_004422/`)
- [x] 1C.5 Plot F1 vs RAM and F1 vs latency for both models. Mark the "knee" point
      (the smallest window that is close to the best F1). (`charts/05_tradeoff.png` in both runs above)
- [ ] 1C.6 Set an IoT budget rule, for example "RAM ≤ X MB and latency ≤ Y ms", then choose the window inside that budget
- [x] 1C.8 SW_XGBoost trade-off, windows 8,16,24,...,64 vs plain XGBoost: point vs time-series attacks,
      live 1-thread RAM / packets/s / latency, charts. Script: `MODELS/MODEL SW_XGBOOST/window_tradeoff.py`.
      Evidence: `runs/sw_xgb_window_tradeoff_20261030_231549/WINDOW_TRADEOFF.md` (FINISHED OK, 22 min)
- [x] 1C.9 Balanced detector (equal weight to single AND time-series attacks): solo training + deviation
      features + multi-scale window (8+56) + plain-XGBoost safety net. Script: `MODELS/MODEL SW_XGBOOST/train_balanced.py`
      Evidence: `runs/sw_xgb_balanced_20261031_000650/BALANCED.md`. Result: BAL_MS beats SW_W16 on single AND
      time-series attacks; ENS (picked on val) adds only +0.2 pp hidden detection for -21% speed.
      LightGBM: `runs/sw_lgbm_balanced_20261031_005302/BALANCED.md`: same ranking; LGBM BAL_MS = same detection
      as XGB BAL_MS, half the RAM (207 vs 411 MB), but false alarms 0.38% vs 0.25%.
- [x] 1C.10 Latency constraint: fast live feature builder (`MODELS/common/live_windows.py`) + gateway drop test
      (`MODELS/MODEL SW_XGBOOST/live_latency.py`): preprocessing vs model time, max flows/s without drops,
      best model per arrival rate. Evidence: `runs/live_latency_20261031_112720/LIVE_LATENCY.md`.
      Live builder = training code (100% same predictions). LGBM BAL_MS: 131 µs pre + 139 µs model = 270 µs/flow,
      max ~3,700 flows/s on 1 thread (was 8.2 ms). XGBoost too slow per single flow (~2 ms model call).
- [x] 1C.11 Retrain WITHOUT the 6 bulk features (version leak, see 3.3): `train_balanced.py --drop-bulk`
      (LightGBM + XGBoost), then `live_latency.py` on the new runs. Evidence: `runs/sw_lgbm_balanced_nobulk_20261031_121031/`,
      `runs/sw_xgb_balanced_nobulk_20261031_121457/`, `runs/live_latency_20261031_122954/`. Detection unchanged
      (LGBM BAL_MS hidden 98.01%, series 91.91%, false alarms 0.34%), 248 µs/flow. 1C.7 re-confirmed: LGBM BAL_MS (no bulk).
      (window_tradeoff --drop-bulk not run; optional)
- [x] 1C.7 **Final choice in Phase 1:** best SW model (XGB or LGBM) + window size. Write the reason in `MODELS/results/BEST_MODEL.md`
      Chosen: **LightGBM BAL_MS, no bulk features** (64 flow features, windows 8+56 + deviation, solo training).
      Runner-up: XGBoost BAL_MS (fewer false alarms, 2x RAM, 10x slower per flow).

### 1D. Robustness (optional, already started)
- [x] 1D.1 Solo-attack training (attacks hidden among normal flows). Evidence: `MODELS/results/SOLO_TRAINING.md`
- [x] 1D.2 SW_XGB_ROBUST (without the 6 bulk features). Evidence: `MODELS/MODEL SW_XGBOOST/robust/w32/` (val F1 0.988)

---

## Phase 2 — Suricata setup and requirements

- [x] 2.1 Install Suricata + ET Open rules. Guide: `MODELS/Suricata/INSTALL.md`
- [x] 2.2 Run Suricata on each CIC-IDS2017 day pcap. Evidence: `MODELS/Suricata/output/<Day>/suricata/`
- [~] 2.3 Write down Suricata's needs: version, rule count, CPU threads, peak RAM, disk, packets/s
      (Raw numbers exist in each day's `perf.json`: Suricata 8.0.7, single thread, 570-980 MB peak RAM. The .md summary is not written yet)
      (from `perf.json` / `stats.log` for each day), in `MODELS/Suricata/SURICATA_REQUIREMENTS.md`
- [~] 2.4 Decide how alerts are counted (ALL vs THREATS only) and keep the same rule for every day

---

## Phase 3 — CICFlowMeter v4 flows for CIC-IDS2017 (to match TRUST Lab)

Why: TRUST Lab flows were made with **CICFlowMeter v4**. The CIC-IDS2017 CSVs were made with **v3**.
The features differ, so the TRUST Lab model cannot be tested fairly on the v3 CSVs.

- [~] 3.1 Install CICFlowMeter v4 (Java). The tool is in `/home/abhinav_iot/tools/`.
      Check its version and write down the exact build used.
      (Checked 2026-10-31: Java = OpenJDK 11.0.32; `tools/CICFlowMeter-4.0/` + `tools/CICFlowMeter/` + gradle-4.2 exist.
      Java output already exists for the sample only: `DataSet/cfm_java/wed_sample.pcap_Flow.csv`.
      No full-day flow CSVs yet (Java or Python). Disk: 16 TB free.)
      Launcher: `/home/abhinav_iot/tools/CICFlowMeter-4.0/bin/cfm <pcap> <out dir>`.
      Script for 3.2-3.4: `MODELS/Suricata/cicids_cfm4_flows.py` (`--sample` first, then the 4 days). (written, not run yet)
- [ ] 3.2 Small test: convert `wed_sample.pcap`. Check that the column names and order match TRUST Lab `FEATURE_DESCRIPTIONS.txt`
- [~] 3.3 Compare a few feature values with TRUST Lab rules (packet lengths, bulk features, IAT units)
      Sample done (`runs/cicids_cfm4_flows_20261031_120140/COLUMN_CHECK.md`): all 70 features present after the
      48-name map; units look the same (µs). ⚠ FOUND A LEAK: the 6 bulk features are always 0 in TRUST Lab Benign/DDoS/
      DoS/PortScan/Slowloris (old cfm version) but non-zero in the other 10 attack classes (new version).
      BAL_MS uses them. Next: retrain without the 6 bulk features (TRUST Lab only) — see BEST_MODEL.md section 7.
- [~] 3.4 Convert the full pcap of each day: **Tuesday, Wednesday, Thursday, Friday** (Monday is all normal, so skip it for testing)
      (Wednesday only, made with the Python cicflowmeter, NOT Java v4: `output/Wednesday/v4/flows_v4.parquet`)
      Java 4.0 done for all 4 days: `runs/cicids_cfm4_flows_20261031_120154/` (Tue 386,846 / Wed 777,036 / Thu 410,454 /
      Fri 695,256 flows, all packets read). ⚠ BUT Java counts PAYLOAD length; TRUST Lab counts the FULL Ethernet frame
      (TCP Pkt Len Min = 54/60/66 in TRUST Lab, 0 in Java for 44% of flows). The Python cicflowmeter counts the full
      frame like TRUST Lab -> decision needed on which tool to use (see reply 2026-10-31).
      DECIDED (user, option A): Python cicflowmeter + TRUST Lab rules. Script `MODELS/Suricata/cicids_pyflows.py`
      (cfm-py) for Tue/Thu/Fri; Wednesday = `DataSet/wed_py/wed_py.csv`. Java flows kept only as a reference.
      Labelling + evaluation: `MODELS/Suricata/cicids_week_eval.py` (covers 3.5, 3.6 and Phase 4). (written, not run yet)
- [~] 3.5 Label the v4 flows using the attack time schedule / 5-tuple from the v3 labelled CSVs
- [ ] 3.6 Sanity check for each day: flow count, attack count per label, share of unmatched flows
- [ ] 3.7 Save as `<Day>_v4_labelled.parquet` with the same columns as TRUST Lab

---

## Phase 4 — Best SW model vs Suricata on CIC-IDS2017 (Tuesday to Friday)

Decision (user, 2026-10-31): **NO retraining. CIC-IDS2017 is test data only**, new to both detectors.
Detectors in each test:
- LightGBM BAL_MS (the 1C.7 choice), trained on TRUST Lab only
- Suricata ALL
- Suricata THREATS
Scored as attack vs normal + detection rate per CIC-IDS label (no class mapping needed, since the model is not retrained).

- [~] 4.1 Wednesday comparison. Done with Python-cicflowmeter flows: `MODELS/Suricata/output/Wednesday/v4/RESULTS_V4.md`.
      ⚠ The TRUST Lab model detected only ~0.06% here, because of the feature/tool mismatch. Redo it with the Phase 3 flows.
- [ ] 4.2 Tuesday: separate metrics table
- [x] 4.3 Wednesday: separate metrics table (redo). Evidence: `runs/cicids_week_eval_20261031_222731/WEEK_RESULTS.md`.
      BAL_MS (TRUST Lab only) 0.13% detection / 5.04% false alarms; FLAT 4.87% / 10.07%; Suricata ALL 91.15% / 12.76%;
      Suricata THREATS 0.00% / 0.08%. => TRUST Lab models do NOT transfer to CIC-IDS2017 Wednesday (DoS attacks).
- [ ] 4.4 Thursday: separate metrics table
- [ ] 4.5 Friday: separate metrics table
- [~] 4.6 Measure each detector on every day: (Wednesday only so far)
  - [ ] Detection rate, false alarm rate, precision, F1
  - [ ] Detection per attack type
  - [ ] Time to detect (attack flows that passed before the first alert)
  - [ ] Speed: packets/s and latency
  - [ ] Peak RAM, CPU use, startup/training time
  - [ ] Design: can it block the first packet? How is a new attack added (new rule vs retraining)?
- [ ] 4.7 One summary table across all 4 days (`cicids_week_eval.py` -> WEEK_RESULTS.md)
- [ ] 4.8 **Conclusion:** which detector is best overall, and which wins in each segment
      (per attack family, false alarms, speed, RAM, time to detect, ease of update).
      Save it as `MODELS/results/ML_VS_SURICATA.md`

---

## Phase 5 — Autoencoder for unknown (zero-day) attacks

Idea: train only on **normal** traffic, so the autoencoder learns to rebuild normal flows well (small reconstruction error).
An attack flow looks different, so its **reconstruction error is higher**.
If the error is above a **threshold**, the flow is flagged as an attack.

### 5A. Data
- [ ] 5A.1 Training data = TRUST Lab **benign flows only** (time-ordered, same split as Phase 1)
- [ ] 5A.2 Validation data = benign flows only (used to set the threshold)
- [ ] 5A.3 Test data = benign + attacks
- [ ] 5A.4 Unknown-attack test: **leave-one-attack-family-out**. The attack family is never seen in training,
      which is always true for an AE, but also check it against the SW model that was trained without that family
- [ ] 5A.5 Scale features (fit the scaler on benign train data only). Use log scaling for heavy-tailed counts

### 5B. Model
- [ ] 5B.1 Dense autoencoder on single flows (small: for example 64→32→8→32→64), in PyTorch on GPU
- [ ] 5B.2 Optional: sliding-window autoencoder (input = window statistics, as in the SW models)
- [ ] 5B.3 Seeds fixed. Early stopping on the validation reconstruction loss
- [ ] 5B.4 Save the model, scaler and threshold into `runs/train_autoencoder_<ts>/`

### 5C. Threshold
- [ ] 5C.1 Threshold = a percentile of the benign validation error (try 95, 99, 99.5, 99.9)
- [ ] 5C.2 Show the trade-off: each percentile vs detection rate and false alarm rate
- [ ] 5C.3 Optional: adaptive threshold (rolling benign error per device/time window), so the threshold moves up or down with normal drift

### 5D. Evaluation
- [ ] 5D.1 Detection rate per attack family (especially the left-out "unknown" families)
- [ ] 5D.2 False alarm rate, ROC-AUC, PR-AUC
- [ ] 5D.3 Latency per flow and peak RAM (IoT fitness)
- [ ] 5D.4 Optional: test on CIC-IDS2017 v4 flows (Phase 3) as a completely new network
- [ ] 5D.5 Compare it with the SW model and Suricata on unknown attacks

---

## Phase 6 — Final system and report

- [ ] 6.1 Proposed design: SW model (known attacks) + autoencoder (unknown attacks) + Suricata (signatures).
      Explain how each one feeds the trust score in `SDP_CONTROLLER/trust_scorer.py`
- [ ] 6.2 Final table: detection, false alarms, RAM, latency, time to detect for every detector
- [ ] 6.3 Charts for the report (F1 vs window, F1 vs RAM, per-day bars, AE error histogram)
- [ ] 6.4 Write `MODELS/results/FINAL_REPORT.md`
