"""
Shared settings for every model.

Change paths or sizes here, not inside the model folders, so that every model
is trained and tested on exactly the same data.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT = Path(__file__).resolve().parent.parent          # .../MODELS

# The TRUST Lab dataset. Override on another PC with:  set TRUSTLAB_DIR=E:\data\trustlab\Datasets
DATASET_DIR = Path(os.environ.get(
    "TRUSTLAB_DIR",
    ROOT.parent / "trustlab_dataset-main" / "trustlab_dataset-main" / "Datasets",
))

DATA_DIR = ROOT / "data"
EXTRACT_DIR = DATA_DIR / "extracted"     # plain .csv after joining the .gz parts
PROCESSED_DIR = DATA_DIR / "processed"   # train / val / test streams (parquet)
RESULTS_DIR = ROOT / "results"           # one <model>.json per model + comparison

# ---------------------------------------------------------------- classes
# The label is taken from the folder name, because the "Label" column inside the
# files is not consistent (e.g. "dos", "Explotacion", "C2Beac", "webbased").
BENIGN = "Benign"
CLASSES = [
    "Benign", "API", "Bruteforce", "BufferOverflow", "C2Beaconing", "DDoS", "DNS",
    "DoS", "Evasion", "Exfiltration", "Exploitation", "MITM", "PortScan",
    "Slowloris", "TLSSSL", "WebBased",
]
CLASS_TO_ID = {c: i for i, c in enumerate(CLASSES)}

# Label spellings found in TRUST Lab files (and common variants) -> our class names.
# Used when a CSV with a "Label" column is given to predict.py or to Suricata.
LABEL_ALIASES = {c.lower(): c for c in CLASSES}
LABEL_ALIASES.update({
    "normal": "Benign", "explotacion": "Exploitation", "exfiltracion": "Exfiltration",
    "c2beac": "C2Beaconing", "c2": "C2Beaconing", "service exploitation": "Exploitation",
})

# ---------------------------------------------------------------- columns
TIME_COL = "Timestamp"
# Not used as model input:
#   IPs and Src Port are randomised per row in this dataset (no real meaning),
#   Timestamp is only used to put flows in time order.
DROP_COLS = ["Src IP", "Dst IP", "Src Port", "Timestamp", "Label", "Source File", "CWR Flag Cnt"]

# Two CICFlowMeter versions were used: the old one writes "CWE Flag Count" (a typo for CWR),
# the new one writes "CWR Flag Cnt". Same feature -> rename new name to the old name,
# but only when the file does not already have the old name (Benign has both; its CWR column is empty).
COLUMN_ALIASES = {"CWR Flag Cnt": "CWE Flag Count"}

# Features used for the window statistics (sliding-window models).
# A small set keeps the number of window features manageable.
WINDOW_STAT_FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Pkt Len Mean",
    "SYN Flag Cnt", "RST Flag Cnt", "ACK Flag Cnt", "Init Fwd Win Byts",
]

# ---------------------------------------------------------------- sampling
SEED = 42
MAX_FLOWS_PER_ATTACK = 60_000     # per attack class (before the 70/15/15 split)
MAX_FLOWS_BENIGN = 1_200_000      # benign is the "background" traffic, so it is larger
QUICK_ATTACK = 3_000              # --quick mode: tiny run to check that the code works
QUICK_BENIGN = 60_000

SPLIT = (0.70, 0.15, 0.15)        # train / val / test, in time order inside each class

# ---------------------------------------------------------------- time stream
# Attack flows are inserted into benign traffic as "bursts".
BURST_MIN, BURST_MAX = 200, 2_000           # attack flows per burst
ATTACK_SHARE_MIN, ATTACK_SHARE_MAX = 0.5, 0.95  # share of attack flows inside a burst
BACKGROUND_SHARE = 0.5                       # share of benign flows used as gaps between bursts

# ---------------------------------------------------------------- windows
WINDOW = 32        # number of flows in one window (current flow + 31 before it)
