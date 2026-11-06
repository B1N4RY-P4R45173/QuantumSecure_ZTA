# Known-Attack Detection Experiment — TRUST Lab Dataset

This folder trains 5 ML models on the same time-ordered traffic, measures Suricata,
and compares all of them for **known attacks**.

| Folder | Model | What it sees |
|---|---|---|
| `MODEL XGBOOST` | XGBoost | One flow (no time) — baseline |
| `MODEL LIGHTGBM` | LightGBM | One flow (no time) — baseline |
| `MODEL SW_XGBOOST` | Sliding-window XGBoost | Current flow + statistics of the last 32 flows |
| `MODEL SW_LIGHTGBM` | Sliding-window LightGBM | Current flow + statistics of the last 32 flows |
| `MODEL LSTM` | LSTM neural network | The last 32 flows, in order |
| `MODEL SURICATA` | Suricata (real) | Packets — needs a pcap, see its README |

---

## 1. Setup (any PC)

```powershell
cd MODELS
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

The dataset is expected at `..\trustlab_dataset-main\trustlab_dataset-main\Datasets`.
If it is somewhere else on the other PC, set its path first:

```powershell
$env:TRUSTLAB_DIR = "E:\data\trustlab_dataset-main\trustlab_dataset-main\Datasets"   # PowerShell
export TRUSTLAB_DIR=/data/trustlab_dataset-main/trustlab_dataset-main/Datasets       # Linux
```

You need about **8 GB of free disk** (decompressed CSVs) and **16 GB RAM** is recommended.

## 2. Run

**First, a quick test.** It uses small data and checks that everything works:

```powershell
.\run_all.ps1 -Quick             # Linux: ./run_all.sh --quick
```

**Then the full run:**

```powershell
.\run_all.ps1                    # Linux: ./run_all.sh
```

Or step by step:

```powershell
python preprocess.py                      # once (first time also decompresses the data)
python "MODEL XGBOOST\train.py"
python "MODEL LIGHTGBM\train.py"
python "MODEL SW_XGBOOST\train.py"
python "MODEL SW_LIGHTGBM\train.py"
python "MODEL LSTM\train.py"
python compare.py
```

Suricata runs on Linux/WSL only. See `MODEL SURICATA\README.md`.

### Set up and train one model on its own (Windows, NVIDIA GPU)

Every model folder has its own scripts. Open **Windows Terminal**, go into the model folder, and run:

```powershell
cd "D:\BTECH\ZEROTRUST\PQZTA\MODELS\MODEL XGBOOST"
.\setup.bat          # once: Python env + packages + GPU check + data
.\train.bat          # train on TRUST Lab, save the model in output\
.\predict.bat        # use the saved model (no training)
```

| File | What it does |
|---|---|
| `setup.bat` / `setup.ps1` | Creates/uses the shared `MODELS\.venv`, installs this model's `requirements.txt`, checks the GPU, prepares the data if needed |
| `train.bat` / `train.ps1` | Trains on TRUST Lab and **saves the model** in `output\` |
| `predict.bat` / `predict.py` | **Loads the saved model** and predicts |
| `requirements.txt` | Packages for this model only |

The `.bat` files work even when Windows blocks PowerShell scripts (they use `-ExecutionPolicy Bypass`).

| Model | Trains on | Saved model |
|---|---|---|
| XGBOOST, SW_XGBOOST | NVIDIA GPU (CUDA) | `output\model.json` |
| LIGHTGBM, SW_LIGHTGBM | CPU (the pip package has no GPU support) | `output\model.txt` |
| LSTM | NVIDIA GPU (CUDA). `setup.bat` installs PyTorch **with CUDA** (`cu126`) | `output\model.pt` |

Options:
- `.\setup.bat -AllData`: prepare **every** flow instead of the default sample (slow, needs about 16 GB RAM).
- `.\train.bat -Device cpu`: train on the CPU.
- `.\train.bat --trees 600` or, for the LSTM, `.\train.bat --epochs 12`: extra options go to `train.py`.
- LSTM: `.\setup.bat -Cuda cu130` if `cu126` doesn't work with your driver.

**Speed is always measured on the CPU**, even when the model trained on the GPU,
because an edge gateway has no GPU. Each `results\<MODEL>.json` records `train_device` and `speed_measured_on`.

**All models must use the same data.** If the data changes (for example from quick to full, or to `-AllData`),
train every model again. Otherwise the comparison isn't fair.

The Python files can also be run directly:

| File | What it does |
|---|---|
| `train.py` | Trains the model, tests it, and **saves it** in `output\` |
| `predict.py` | **Loads the saved model** and predicts — no training |

```powershell
python "MODEL SW_XGBOOST\train.py"                       # train + save
python "MODEL SW_XGBOOST\predict.py"                     # use saved model on the test stream
python "MODEL SW_XGBOOST\predict.py" --csv new_flows.csv # use saved model on new CICFlowMeter flows
```

`predict.py` writes `output\predictions_<input>.csv` with `predicted_class`, `confidence`
and `is_attack` for each flow. If the CSV has a `Label` column, it also prints the metrics.
Window models (SW_*, LSTM) need flows in time order. The first 31 flows get no
prediction, because there is not enough history yet.

## 3. Output

| File | Content |
|---|---|
| `results\<MODEL>.json` | All metrics of one model (same format for every model) |
| `MODEL <NAME>\output\report.txt` | Readable report with per-class precision / recall / F1 |
| `MODEL <NAME>\output\model.*` | The trained model (`.json` XGBoost, `.txt` LightGBM, `.pt` LSTM) |
| `MODEL <NAME>\output\model_info.json` | Class names + settings needed to reuse a tree model |
| `results\COMPARISON.md` | Tables + decision — use this in your report |
| `results\charts\*.png` | Bar charts |

---

## 4. How the data is prepared (important for your report)

What we found in the dataset, and what the code does about it:

| Fact in the dataset | What the code does |
|---|---|
| Each class was recorded in a **separate session** (each file has only one class) | Builds a **mixed time stream**: attack *bursts* (200–2000 flows) are placed inside benign traffic, with 50–95% attack flows inside a burst |
| **IP addresses are random on every row** | IPs and source port are **not** used. Windows are "the last 32 flows", not "the last 32 flows of one host" |
| Label names are not consistent (`dos`, `Explotacion`, `C2Beac`, `webbased` ...) | The **folder name** is used as the label |
| `PortScan.csv.gz` is cut off at the end | The readable part (≈107k flows) is kept, and a warning is printed |
| Benign has 2 extra columns | Columns are selected by name |
| Some values are `inf` (division by zero in CICFlowMeter) | Replaced by 0 |

**Train/val/test split is by time** (first 70% / next 15% / last 15% of each class),
*before* the stream is built. Windows overlap, so a random split would put almost the
same window in both train and test and make the results look too good.

**Sampling:** at most 60,000 flows per attack class and 1,200,000 benign flows,
taken as contiguous time blocks. Change these in `common/config.py`.

## 5. What is measured

| Test | Metric | Why it matters |
|---|---|---|
| Detection | Attack/benign F1, detection rate, false positive rate | Does it catch known attacks without false alarms? |
| Detection | Macro F1 over 16 classes, per-class detection rate | Does it name the attack correctly? |
| Time to detect | Attack flows that pass before the first alert, per burst | How fast does it react? |
| Speed | Flows/s → equivalent packets/s, latency for one input | Can it keep up with line rate? |
| Resources | Peak RAM, training time, model size | Can it run on a small gateway? |
| Design | Waits for flow end? Can block the first packet? | Can it *prevent*, or only *detect*? |

## 6. Limits — write these in your report

- **Suricata cannot run on this dataset** (no pcaps). Without a labelled pcap, only Suricata's speed and RAM are measured, not its detection. `compare.py` shows such values as "n/m" (not measured) and never invents them.
- **ML speed is optimistic.** The ML numbers do not include CICFlowMeter, the step that turns packets into flow features. Suricata's numbers include all packet processing.
- **ML models must wait for the flow to end** (CICFlowMeter features need the whole flow), so they can detect but cannot block the first packets of an attack. Suricata can.
- **The mixed stream is built by us**, not recorded. It is realistic in order and mixing, but it is not a real network capture.
- **Known attacks only.** All attack classes appear in training. Zero-day testing (leave-one-attack-out) is a separate experiment.
