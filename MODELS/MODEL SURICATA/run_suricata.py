"""
MODEL SURICATA — run real Suricata on a pcap and save results in the same format
as the ML models (results/SURICATA.json).

Suricata reads *packets*, but the TRUST Lab dataset only has CSV flow features
(no pcap). So this script works in two modes:

  A) Speed only  (any pcap):
       python run_suricata.py --pcap traffic.pcap
     -> packets/s, Mbit/s, RAM, startup time, number of alerts

  B) Speed + detection  (pcap + labelled flows made from the SAME pcap with CICFlowMeter):
       python run_suricata.py --pcap traffic.pcap --labels flows_labelled.csv
     -> also detection rate, false positive rate, detection rate per attack class,
        and time to detect (attack flows before the first alert)

Run on Linux or WSL (Ubuntu):  sudo apt install suricata && sudo suricata-update
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import psutil

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common import config as C                        # noqa: E402
from common.metrics import binary_metrics, save_result, time_to_detect  # noqa: E402

PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1, "IPV6-ICMP": 58}
ALIASES = C.LABEL_ALIASES


# ---------------------------------------------------------------- running Suricata
def run_measured(cmd: list[str]) -> tuple[float, float, str]:
    """Run a command; return (seconds, peak RAM MB incl. children, stdout+stderr)."""
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ps = psutil.Process(proc.pid)
    peak = 0.0
    while proc.poll() is None:
        try:
            rss = ps.memory_info().rss + sum(c.memory_info().rss for c in ps.children(recursive=True))
            peak = max(peak, rss / 2**20)
        except psutil.Error:
            pass
        time.sleep(0.05)
    out = proc.stdout.read()
    secs = time.perf_counter() - t0
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{out[-3000:]}")
    return secs, peak, out


def packets_and_bytes(log_text: str, eve: Path) -> tuple[int, int]:
    m = re.findall(r"(\d+) packets, (\d+) bytes", log_text)
    if m:
        return int(m[-1][0]), int(m[-1][1])
    pkts = byts = 0                               # fallback: last "stats" event in eve.json
    with eve.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"event_type":"stats"' in line:
                d = json.loads(line)["stats"]["decoder"]
                pkts, byts = d.get("pkts", 0), d.get("bytes", 0)
    return pkts, byts


def read_alerts(eve: Path) -> pd.DataFrame:
    rows = []
    with eve.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"event_type":"alert"' not in line:
                continue
            e = json.loads(line)
            rows.append({
                "ts": pd.Timestamp(e["timestamp"]).timestamp(),
                "proto": PROTO.get(str(e.get("proto", "")).upper(), -1),
                "a": (e.get("src_ip"), e.get("src_port", 0)),
                "b": (e.get("dest_ip"), e.get("dest_port", 0)),
                "signature": e["alert"].get("signature"),
                "category": e["alert"].get("category"),
            })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- matching alerts to flows
def flow_key(proto, a, b):
    return (int(proto), frozenset([a, b]))       # same key for both directions


def parse_times(s: pd.Series) -> np.ndarray:
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.9:
        return num.to_numpy(np.float64)
    return pd.to_datetime(s, dayfirst=True, errors="coerce").map(pd.Timestamp.timestamp).to_numpy(np.float64)


def match(flows: pd.DataFrame, alerts: pd.DataFrame, tolerance_s: float, offset_s: float) -> np.ndarray:
    """True for every flow that has at least one Suricata alert during its lifetime."""
    by_key = defaultdict(list)
    for r in alerts.itertuples():
        by_key[flow_key(r.proto, r.a, r.b)].append(r.ts)
    by_key = {k: np.sort(v) for k, v in by_key.items()}

    start = parse_times(flows["Timestamp"]) + offset_s
    dur = pd.to_numeric(flows["Flow Duration"], errors="coerce").fillna(0).to_numpy() / 1e6  # µs -> s
    hit = np.zeros(len(flows), bool)
    for i, r in enumerate(flows[["Protocol", "Src IP", "Src Port", "Dst IP", "Dst Port"]].itertuples(index=False)):
        ts = by_key.get(flow_key(r[0], (r[1], int(r[2])), (r[3], int(r[4]))))
        if ts is None or np.isnan(start[i]):
            continue
        j = np.searchsorted(ts, start[i] - tolerance_s)
        hit[i] = j < len(ts) and ts[j] <= start[i] + dur[i] + tolerance_s
    return hit


def main() -> None:
    ap = argparse.ArgumentParser(description="benchmark Suricata on a pcap")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--labels", help="CICFlowMeter CSV of the same pcap, with a Label column")
    ap.add_argument("--rules", default="/var/lib/suricata/rules/suricata.rules")
    ap.add_argument("--config", default=None, help="suricata.yaml (default: system config)")
    ap.add_argument("--runmode", default="autofp", help="autofp (all cores) or single (one core)")
    ap.add_argument("--tolerance", type=float, default=2.0, help="seconds of clock difference allowed")
    ap.add_argument("--time-offset", type=float, default=0.0,
                    help="seconds to add to CSV times (e.g. if CICFlowMeter wrote local time)")
    args = ap.parse_args()

    if not shutil.which("suricata"):
        raise SystemExit("suricata not found. On Linux/WSL: sudo apt install suricata && sudo suricata-update")
    pcap = Path(args.pcap).resolve()
    out = HERE / "output" / time.strftime("run_%Y%m%d_%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    base = ["suricata", "-S", args.rules] + (["-c", args.config] if args.config else [])
    print("1) measuring startup (loading rules) ...")
    startup_s, _, _ = run_measured(base + ["-T", "-l", str(out)])

    print(f"2) running Suricata on {pcap.name} (runmode={args.runmode}) ...")
    total_s, peak_mb, log = run_measured(base + ["-r", str(pcap), "-l", str(out), "-k", "none",
                                                 "--runmode", args.runmode])
    (out / "stdout.log").write_text(log, encoding="utf-8")
    suri_log = out / "suricata.log"
    log_all = log + (suri_log.read_text(encoding="utf-8", errors="replace") if suri_log.exists() else "")
    pkts, byts = packets_and_bytes(log_all, out / "eve.json")
    engine_s = max(total_s - startup_s, 1e-9)
    alerts = read_alerts(out / "eve.json")
    print(f"   {pkts:,} packets, {byts / 2**20:.1f} MB, {len(alerts):,} alerts, "
          f"engine {engine_s:.1f}s (+ startup {startup_s:.1f}s)")

    result = {
        "family": "Suricata (rules / signatures, deterministic)",
        "input": "packets (inline, per packet)",
        "window_flows": 0,
        "needs_flow_end": False,
        "can_drop_first_packet": True,
        "quick_data": False,
        "detection": None,
        "performance": {
            "pcap": pcap.name, "packets": pkts, "bytes": byts, "alerts": len(alerts),
            "startup_s": startup_s, "engine_s": engine_s, "runmode": args.runmode,
            "equiv_packets_per_s": pkts / engine_s,
            "throughput_mbit_per_s": byts * 8 / engine_s / 1e6,
            "latency_ms_single": None,
            "peak_ram_mb": peak_mb,
            "train_time_s": 0.0,
            "model_size_mb": Path(args.rules).stat().st_size / 2**20 if Path(args.rules).exists() else None,
        },
        "notes": [
            "Detection is measured only when --labels is given (labelled flows from the same pcap).",
            "Throughput includes packet decoding and reassembly; ML throughput does not include CICFlowMeter.",
        ],
    }

    if args.labels:
        print("3) matching alerts to labelled flows ...")
        flows = pd.read_csv(args.labels, low_memory=False)
        flows.columns = [c.strip() for c in flows.columns]
        flows["cls"] = flows["Label"].astype(str).str.strip().str.lower().map(ALIASES)
        unknown = flows["cls"].isna().sum()
        if unknown:
            print(f"   WARNING: {unknown} flows with unknown labels are skipped: "
                  f"{flows.loc[flows['cls'].isna(), 'Label'].unique()[:10]}")
        flows = flows.dropna(subset=["cls"])
        flows["t"] = parse_times(flows["Timestamp"])
        flows = flows.sort_values("t", kind="stable").reset_index(drop=True)
        hit = match(flows, alerts, args.tolerance, args.time_offset)

        y_true = flows["cls"].map(C.CLASS_TO_ID).to_numpy()
        benign = C.CLASS_TO_ID[C.BENIGN]
        # Suricata says "attack / not attack", not our class names: an alert = "some attack"
        y_pred = np.where(hit, np.where(y_true == benign, -1, y_true), benign)
        # attack "bursts" = runs of the same attack class in time order
        change = np.r_[True, y_true[1:] != y_true[:-1]]
        burst = np.where(y_true != benign, np.cumsum(change), -1)

        per_class = {}
        for c in C.CLASSES:
            m = y_true == C.CLASS_TO_ID[c]
            if m.any():
                per_class[c] = {"support": int(m.sum()),
                                "detection_rate": float(hit[m].mean()) if c != C.BENIGN else None,
                                "alert_rate": float(hit[m].mean())}
        result["detection"] = {
            "accuracy": None, "macro_f1": None,       # Suricata does not output our 16 classes
            "binary": binary_metrics(y_true, y_pred),
            "per_class": per_class,
            "time_to_detect": time_to_detect(y_pred, burst),
            "top_signatures": alerts["signature"].value_counts().head(15).to_dict() if len(alerts) else {},
        }
        b = result["detection"]["binary"]
        print(f"   detection rate {b['recall_detection_rate']:.4f}  FPR {b['false_positive_rate']:.5f}  F1 {b['f1']:.4f}")

    (out / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    save_result("SURICATA", result)


if __name__ == "__main__":
    main()
