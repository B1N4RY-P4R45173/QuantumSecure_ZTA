# Stage 1 decision: best known-attack model for the IoT gateway (TRUST Lab)

Decided 2026-10-31 (CHECKLIST 1C.7). All numbers come from the runs listed in section 6.

## 0. UPDATE 2026-10-31: the chosen model is now LightGBM BAL_MS **without the 6 bulk features**

The bulk features leak the CICFlowMeter version in TRUST Lab (section 7), so the model was retrained without them, on TRUST Lab only.
**Detection did not get worse**, so the leak did not inflate the Stage 1 numbers. The other features already separate those classes.

| TEST_ORIGINAL | LGBM BAL_MS, 70 features (old) | **LGBM BAL_MS, 64 features, no bulk (CHOSEN)** | XGB BAL_MS, no bulk (runner-up) |
|---|---|---|---|
| Hidden single attacks detected | 98.01% | **98.01%** | 97.80% |
| Attack start detected | 97.08% | **97.08%** | 96.79% |
| Single-flow attacks: right class | 99.64% | **99.65%** | 99.69% |
| Time-series attacks: right class | 91.23% | **91.91%** | 91.63% |
| False alarm rate | 0.38% | **0.34%** | 0.22% |
| Macro F1 | 0.9534 | **0.9574** | 0.9569 |
| Balance score (test / validation) | 96.15 / 93.38 | **96.40 / 93.01** | 96.25 / 93.09 |
| Live time per flow (fast builder, 1 thread) | 266 µs | **248 µs** | 2,504 µs |
| Max flows/s without drops (1,024-flow buffer) | 3,759 | **4,059** | 400 |
| Live process RAM | 207 MB | **206 MB** | 437 MB |

- **Model file:** `runs/sw_lgbm_balanced_nobulk_20261031_121031/models/BAL_MS/model.txt`. Input = 64 flow features + 8-flow and 56-flow window statistics + deviation on 8 = **193 features**.
- **Live use:** `MODELS/common/live_windows.py` (same inputs as training, 100% same predictions). Latency evidence: `runs/live_latency_20261031_122954/LIVE_LATENCY.md`.
- **XGBoost** has fewer false alarms but is 10 times slower one flow at a time (about 2.5 ms per call), so it can't keep up at a gateway on 1 thread.
- Sections 1 to 6 below describe the first (70-feature) version. Their conclusions still hold.

## 1. Choice

**LightGBM BAL_MS**: a balanced sliding-window LightGBM model.

| Property | Value |
|---|---|
| Algorithm | LightGBM, multiclass (16 classes: Benign + 15 attacks) |
| Input | current flow (70 CICFlowMeter features) + statistics of the last **8** flows + statistics of the last **56** flows + deviation of the current flow from its 8-flow window = **199 features** |
| Training data | TRUST Lab train split, arranged as attack bursts **plus solo attacks** (1-5 attack flows among normal flows) |
| Model file | `runs/sw_lgbm_balanced_20261031_005302/models/BAL_MS/model.txt` (+ `model_info.json`) |
| Code | `MODELS/MODEL SW_XGBOOST/train_balanced.py --algo lightgbm` (feature builder: `build_X`) |

**Why this model:** it gives **equal importance to single attacks and time-series attacks**. Both kinds damage the system, and older models were good at only one of them. It also has the **lowest RAM** of the models that are good at both.

**Runner-up:** XGBoost BAL_MS. It has the same detection and fewer false alarms (0.25% vs 0.38%), but **twice the RAM** (411 vs 207 MB). Pick it if false alarms matter more than RAM on the target device.

## 2. Evidence: detection (TEST_ORIGINAL, 315k flows, fair for every model)

| Metric | Plain LightGBM (1 flow) | SW-LightGBM W16 | **LightGBM BAL_MS** | XGBoost BAL_MS |
|---|---|---|---|---|
| Attack/benign F1 | 0.9828 | 0.9955 | **0.9953** | 0.9962 |
| False alarm rate | 1.58% | 0.29% | **0.38%** | 0.25% |
| Macro F1 (right class, 16 classes) | 0.8733 | 0.9380 | **0.9534** | 0.9551 |
| Hidden single attacks detected | 99.58% | 95.07% | **98.01%** | 97.27% |
| Attack start detected (first 5 flows) | 99.71% | 93.87% | **97.08%** | 96.20% |
| Single-flow attacks: right class | 91.90% | 99.22% | **99.64%** | 99.74% |
| Time-series attacks: right class | 82.40% | 88.52% | **91.23%** | 91.32% |
| Balance score | 90.75% | 94.06% | **96.15%** | 95.98% |

TEST_SOLO (the same test flows with many solo attacks): BAL_MS catches **95.79%** of solo attacks (XGBoost BAL_MS 95.03%, SW-LightGBM W16 93.02%).

**Balance score** = harmonic mean of: hidden single-attack detection, single-flow attacks right class, and time-series attacks right class. It is only high when all three are high.

## 3. Evidence: chosen on validation, not on test

Validation stream (solo + burst arrangement of the val split, harder than test):

| Metric | LGBM SW_W16 | LGBM BAL_W16 | **LGBM BAL_MS** | LGBM ENS | XGB BAL_MS |
|---|---|---|---|---|---|
| Balance score | 90.87% | 91.99% | **93.38%** | 93.80% | 92.74% |
| False alarm rate | 1.91% | 2.12% | **1.85%** | 1.94% | 1.43% |
| Hidden single attacks detected | 89.21% | 92.63% | **91.88%** | 93.00% | 90.80% |
| Time-series attacks: right class | 87.13% | 86.28% | **90.50%** | 90.51% | 89.80% |

The script's automatic pick was **ENS** (BAL_MS + plain LightGBM safety net, threshold 0.98). It was **not** adopted, because it gains only about 0.3 points on hidden attacks but runs two models and is about 20% slower (153k vs 192k packets/s). BAL_MS is the practical choice for one IoT device.

## 4. Evidence: IoT cost (live test, 1 CPU thread, separate process)

| Model | Live process RAM | Model size | Packets/s | Latency per flow |
|---|---|---|---|---|
| Plain LightGBM (1 flow) | 202 MB | 3.1 MB | 709,576 | 0.36 ms |
| SW-LightGBM W16 | 206 MB | 5.4 MB | 290,729 | 3.36 ms |
| **LightGBM BAL_MS** | **207 MB** | **5.8 MB** | **192,254** | **8.22 ms** |
| LightGBM ENS | 226 MB | 8.9 MB | 152,911 | 8.60 ms |
| XGBoost BAL_MS | 411 MB | 19.2 MB | 191,579 | 10.12 ms |

- RAM includes Python, pandas and the model library (about 185 MB). The BAL_MS model itself takes about **8 MB**.
- Packets/s = flows/s × 17.35 average packets per flow. It does **not** include CICFlowMeter.
- Latency is mostly pandas building the window features, not the model. A numpy rewrite of the window code should lower it.

## 5. What we learned on the way

1. **Window size trade-off** (8 to 64 flows, step 8, both algorithms): a bigger window gives fewer false alarms and better time-series classification, but **misses more hidden single attacks**. For example, SW-LightGBM goes from 97.8% (W8) to 91.8% (W32) of hidden attacks caught. No single window is good at both.
2. **Plain (1-flow) models** are best at hidden single attacks (about 99.6%) and are the fastest, but they have **5 to 7 times more false alarms** (about 1.5%) and name time-series attacks badly (about 82%).
3. **What fixed the trade-off:**
   - training with solo attacks
   - deviation features
   - two windows (8 + 56)
   
   Together they lifted hidden-attack detection from 95.1% to 98.0% **and** time-series classification from 88.5% to 91.2% compared with SW W16.
4. **LightGBM vs XGBoost:** detection is the same within about 1 point at every window. LightGBM needs **half the RAM**, a model **3 times smaller**, and has about 35% lower latency. XGBoost has slightly fewer false alarms.

## 6. Source runs (on PC 2, under `runs/`)

| Run | What |
|---|---|
| `sw_xgb_window_tradeoff_20261030_231549/` | XGBoost: plain vs SW windows 8..64 (`WINDOW_TRADEOFF.md`, charts) |
| `sw_lgbm_window_tradeoff_20261031_004422/` | LightGBM: plain vs SW windows 8..64 |
| `sw_xgb_balanced_20261031_000650/` | XGBoost: FLAT, SW_W16, BAL_W16, BAL_MS, ENS (`BALANCED.md`, charts) |
| `sw_lgbm_balanced_20261031_005302/` | **LightGBM: FLAT, SW_W16, BAL_W16, BAL_MS, ENS (chosen model)** |

Earlier context: `MODELS/results/COMPARISON.md` (5-model comparison, window 32) and `MODELS/results/SOLO_TRAINING.md` (first solo-attack experiment).

## 7. Limits (read before Stage 4)

- ⚠ **DATA LEAK FOUND 2026-10-31: the 6 bulk features.** TRUST Lab was made with two CICFlowMeter versions:
  - Benign, DDoS, DoS, PortScan and Slowloris come from the old version, whose 6 bulk features
    (`Fwd/Bwd Byts/b Avg`, `Fwd/Bwd Pkts/b Avg`, `Fwd/Bwd Blk Rate Avg`) are **always 0**.
  - The other 10 attack classes come from the new version, where they are **non-zero in 82–100% of flows**.
  
  So "bulk ≠ 0" fingerprints those 10 attack classes, and BAL_MS uses these features (400–760 splits each).

  Consequences:
  1. The Stage 1 numbers for the single-flow attacks are probably **too optimistic**.
  2. On CIC-IDS2017, where the Java CICFlowMeter 4.0 fills bulk for 63% of *normal* flows (in the sample), many false alarms are expected.

  **Fix:** retrain on TRUST Lab without the 6 bulk features, then re-check this choice.
  Evidence: `head`+`awk` scan of `MODELS/data/extracted/*.csv` (first 50k–200k rows per class) and the class headers (CWE = old version, CWR = new).

- **Tested only on TRUST Lab** (known attacks, the same network it was trained on). On CIC-IDS2017 Wednesday, the older SW-XGBoost caught only 0.06–31% of attacks without retraining, because the flow tool and features differ. Stage 3 (CICFlowMeter v4 flows) must come before any fair test on CIC-IDS2017.
- **Known attacks only.** Unknown attacks are the job of the Stage 5 autoencoder.
- **Classes are split into "single-flow" and "time-series" by a rule set in `window_tradeoff.py`:**
  - single-flow: Exploitation, BufferOverflow, WebBased, API, TLSSSL, C2Beaconing, Exfiltration
  - time-series: DDoS, DoS, Slowloris, PortScan, Bruteforce, DNS, MITM, Evasion
- **The hidden-attack and attack-start groups are small** (954 and 685 flows in TEST_ORIGINAL), so differences under about 1 point there are within noise.
- **No `predict.py` exists yet for BAL_MS.** Using it on new data needs the same feature builder (`build_X` in `train_balanced.py`) with windows [8, 56] and deviation on window 8.
- **Every flow needs a full window before it can be scored:** the first 55 flows after the detector starts have no full 56-flow window.
