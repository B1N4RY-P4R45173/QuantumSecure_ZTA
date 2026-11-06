# XGBoost vs Suricata — on the same traffic (CIC-IDS2017)

## Why a second dataset?

Suricata reads **packets**. XGBoost reads **flows** (CSV rows).
TRUST Lab has only flows, so Suricata can't be tested on it.

**CIC-IDS2017** publishes both the **packets (pcap)** and the **labelled flows (CSV)** made from
the same packets. So both detectors can be tested on **exactly the same traffic**.

## What is compared

| Detector | What it is |
|---|---|
| `SURICATA_ALL` | Real Suricata + free ET Open rules. Every alert counts |
| `SURICATA_THREATS` | Same run, but engine events (`SURICATA ...`) and info rules (`ET INFO`, `ET POLICY`) are ignored |
| `XGB_RETRAINED` | XGBoost (one flow), trained on the CIC-IDS2017 train blocks of that day |
| `SW_XGB_RETRAINED` | **SW-XGBoost** (flow + last 32 flows), trained on the CIC-IDS2017 train blocks |
| `XGB_TRUSTLAB` | Your model from `MODEL XGBOOST`, trained only on TRUST Lab (**a network it never saw**) |
| `SW_XGB_TRUSTLAB` | Your model from `MODEL SW_XGBOOST`, trained only on TRUST Lab (**a network it never saw**) |

All are scored on the **same test flows**. The day is cut into 10-minute blocks
(3 train : 2 test), because overlapping windows would leak between train and test with a random split.
The fairest comparison is **Suricata vs `SW_XGB_TRUSTLAB`**: neither was trained on CIC-IDS2017.
The `*_RETRAINED` rows show the best case for ML (it learned from the same day).

| Test | Metric |
|---|---|
| Detection | Detection rate, false positive rate, precision, F1 |
| Per attack type | Share of flows flagged for each CIC-IDS2017 label |
| Time to detect | Attack flows that passed before the first alert |
| Speed / resources | Packets/s, latency, peak RAM, startup or training time |
| Design | Can it block the first packet? How is a new attack added? |

---

## Step 1: Download CIC-IDS2017 (one day is enough to start)

From the official page: https://www.unb.ca/cic/datasets/ids-2017.html

You need **2 things for the same day**:
1. The **pcap** file, for example `Wednesday-workingHours.pcap` (about 13 GB)
2. The **labelled CSV version that includes IP addresses and timestamps**
   (the "GeneratedLabelledFlows" / "TrafficLabelling" CSVs, not the "MachineLearningCSV" ones)

| Day | Attacks in it |
|---|---|
| Monday | None (benign only) |
| Tuesday | FTP-Patator, SSH-Patator (brute force) |
| **Wednesday** (recommended start) | DoS Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed |
| Thursday | Web attacks (brute force, XSS, SQL injection), Infiltration |
| Friday | Bot, PortScan, DDoS |

Put the CSVs in `Suricata\data\csv\`.

**Important for speed:** copy the pcap **into the WSL file system** (for example `~/cicids/`).
Reading a 13 GB file from `/mnt/d` is very slow in WSL, and Suricata would look slower than it really is.

## Step 2: Setup (once, inside WSL Ubuntu)

Full Suricata install and setup guide for Linux and Windows: [INSTALL.md](INSTALL.md).

```powershell
wsl -d Ubuntu-24.04
```
```bash
cd /mnt/d/BTECH/ZEROTRUST/PQZTA/MODELS/Suricata
bash setup_wsl.sh
mkdir -p ~/cicids && cp /path/to/Wednesday-workingHours.pcap ~/cicids/
```

To use the TRUST Lab model (`XGB_TRUSTLAB`), train `MODEL XGBOOST` first (in `MODELS`).

## Step 3: Run

```bash
source ~/pqzta-venv/bin/activate
bash run_day.sh Wednesday ~/cicids/Wednesday-workingHours.pcap data/csv/Wednesday-workingHours.pcap_ISCX.csv
```

Or step by step:

```bash
python step1_suricata.py --day Wednesday --pcap ~/cicids/Wednesday-workingHours.pcap   # Suricata (slow)
python step2_xgboost.py  --day Wednesday --csv data/csv/Wednesday-workingHours.pcap_ISCX.csv
python step3_compare.py  --day Wednesday
```

Step 2 can also run on **Windows** with the normal `.venv`, and it trains on your **NVIDIA GPU**
(`--device cuda`, default: GPU if it works). Speed is always measured on the CPU. Step 1 needs Linux.

## Output

`output\<Day>\COMPARISON.md` has the tables for your report. Raw numbers are in `comparison.json`.

---

## How alerts are matched to flows

- A flow counts as **detected by Suricata** if an alert has the same protocol and both IP:port pairs
  (either direction), and the alert time falls inside the flow's lifetime.
- CIC-IDS2017 CSV times have **minutes only** and **no AM/PM** (`1:05` means 13:05). The code fixes AM/PM
  (the capture ran in working hours) and adds a time tolerance (default 120 s).
- Suricata writes UTC; the CSV uses local Canadian time. The script **finds the hour offset
  automatically**: it tries every hour from −12 to +12 and keeps the one that matches the most flows.
  This uses **no labels**, so it can't favour either detector. Check that it chose a sensible value
  (around −3 h). If needed, set it yourself: `--offset-hours -3`.

## Limits — say these in your report

- **CIC-IDS2017 has known label errors** (Engelen et al., 2021, "Troubleshooting an intrusion detection
  dataset: the CICIDS2017 case study"). Some "false alarms" may be real attacks with a wrong label.
- **Today's Suricata rules are newer than 2017.** Old attacks are already in the rules, so Suricata looks
  better than it would have on the first day of each attack.
- **XGBoost speed is optimistic.** It does not include CICFlowMeter, the step that turns packets into flows.
- **XGB_RETRAINED uses a random 60/40 split of flows from the same day.** This is the usual method, but
  flows from the same attack are in both train and test, so its scores are an upper limit.
