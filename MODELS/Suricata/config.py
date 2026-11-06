"""
Settings for the XGBoost vs Suricata comparison on CIC-IDS2017.

Both detectors are tested on the SAME traffic:
  * Suricata reads the CIC-IDS2017 pcap (packets)
  * XGBoost reads the CIC-IDS2017 labelled flow CSV made from that same pcap
"""

from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent            # .../MODELS/Suricata
MODELS = HERE.parent                              # .../MODELS
DATA = HERE / "data"                              # put pcap/ and csv/ here (see README)
OUT = HERE / "output"                             # everything this folder produces
TRUST_XGB_DIR = MODELS / "MODEL XGBOOST" / "output"   # the model trained on TRUST Lab

SEED = 42
TEST_SHARE = 0.4      # only for --split random

# Time-block split (default): the day is cut into BLOCK_MINUTES blocks, and the blocks follow
# BLOCK_PATTERN again and again (3 train : 2 test = 60/40). Windows overlap, so a random split would
# put almost the same window in train and test (leakage). Blocks keep neighbouring flows together.
BLOCK_MINUTES = 10
BLOCK_PATTERN = ("train", "test", "train", "test", "train")

WINDOW = 32           # flows per window for SW-XGBoost (same as TRUST Lab)
SW_XGB_DIR = MODELS / "MODEL SW_XGBOOST" / "output"   # SW-XGBoost trained on TRUST Lab
SW_XGB_ROBUST_DIR = MODELS / "MODEL SW_XGBOOST" / "robust" / "w32"   # same, without the 6 bulk features

# ------------------------------------------------------------------ CIC-IDS2017 labels
# CIC-IDS2017 label -> TRUST Lab class (only used to show which TRUST class it is closest to;
# the comparison itself is binary: attack vs benign).
CIC_TO_TRUST_CLASS = {
    "BENIGN": "Benign",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "Slowloris", "DoS Slowhttptest": "Slowloris",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "Bruteforce", "SSH-Patator": "Bruteforce",
    "Web Attack Brute Force": "WebBased", "Web Attack XSS": "WebBased",
    "Web Attack Sql Injection": "WebBased",
    "Bot": "C2Beaconing",
    "Infiltration": "Exploitation",
    "Heartbleed": "TLSSSL",
}

# ------------------------------------------------------------------ column names
# CIC-IDS2017 (CICFlowMeter v3 names) -> TRUST Lab (CICFlowMeter v4 names)
CIC_TO_TRUST_COLUMNS = {
    "Destination Port": "Dst Port", "Protocol": "Protocol", "Flow Duration": "Flow Duration",
    "Total Fwd Packets": "Tot Fwd Pkts", "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts", "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max", "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean", "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max", "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean", "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Min Packet Length": "Pkt Len Min", "Max Packet Length": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean", "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "Flow Packets/s": "Flow Pkts/s", "Flow Bytes/s": "Flow Byts/s",
    "Flow IAT Mean": "Flow IAT Mean", "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max", "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Tot", "Fwd IAT Mean": "Fwd IAT Mean", "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max", "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Tot", "Bwd IAT Mean": "Bwd IAT Mean", "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max", "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags", "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags", "Bwd URG Flags": "Bwd URG Flags",
    "FIN Flag Count": "FIN Flag Cnt", "SYN Flag Count": "SYN Flag Cnt", "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt", "ACK Flag Count": "ACK Flag Cnt", "URG Flag Count": "URG Flag Cnt",
    "CWE Flag Count": "CWE Flag Count", "ECE Flag Count": "ECE Flag Cnt",
    "Down/Up Ratio": "Down/Up Ratio", "Average Packet Size": "Pkt Size Avg",
    "Avg Fwd Segment Size": "Fwd Seg Size Avg", "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "Fwd Header Length": "Fwd Header Len", "Bwd Header Length": "Bwd Header Len",
    "Fwd Avg Bytes/Bulk": "Fwd Byts/b Avg", "Fwd Avg Packets/Bulk": "Fwd Pkts/b Avg",
    "Fwd Avg Bulk Rate": "Fwd Blk Rate Avg", "Bwd Avg Bytes/Bulk": "Bwd Byts/b Avg",
    "Bwd Avg Packets/Bulk": "Bwd Pkts/b Avg", "Bwd Avg Bulk Rate": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts", "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts", "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "Init_Win_bytes_forward": "Init Fwd Win Byts", "Init_Win_bytes_backward": "Init Bwd Win Byts",
    "Active Mean": "Active Mean", "Active Std": "Active Std", "Active Max": "Active Max", "Active Min": "Active Min",
    "Idle Mean": "Idle Mean", "Idle Std": "Idle Std", "Idle Max": "Idle Max", "Idle Min": "Idle Min",
}

# columns that identify a flow (used to match Suricata alerts), never used as model input
ID_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]
