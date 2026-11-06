"""
Phase 3: CIC-IDS2017 pcaps -> flow CSVs with the Java CICFlowMeter 4.0 (the tool TRUST Lab used),
then check that the columns match the 70 features the TRUST Lab models were trained on.

    python MODELS/Suricata/cicids_cfm4_flows.py --sample            # wed_sample.pcap only (quick test)
    python MODELS/Suricata/cicids_cfm4_flows.py                     # Tuesday..Friday full pcaps
    python MODELS/Suricata/cicids_cfm4_flows.py --days Monday       # Monday too, if needed

DataSet/ is only READ. The flow CSVs are written to runs/ (they are large).
Runs in pqzta-venv (only the column check uses pandas); the conversion itself is Java.

Saves: runs/cicids_cfm4_flows_<YYYYMMDD_HHMMSS>/
       run.log, config.json, results.json, COLUMN_CHECK.md, flows/<pcap>_Flow.csv, cfm_logs/<Day>.log
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODELS_DIR = HERE.parent
PROJECT_ROOT = MODELS_DIR.parent
sys.path.insert(0, str(MODELS_DIR))
sys.path.insert(0, str(MODELS_DIR / "MODEL SW_XGBOOST"))

import window_tradeoff as wt                                           # noqa: E402  (logging helpers)

# ---------------------------------------------------------------- settings
CFM = Path("/home/abhinav_iot/tools/CICFlowMeter-4.0/bin/cfm")
DATASET_DIR = PROJECT_ROOT / "DataSet"
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "cicids_cfm4_flows"
PCAPS = {
    "Monday": "Monday-WorkingHours.pcap",
    "Tuesday": "Tuesday-WorkingHours.pcap",
    "Wednesday": "Wednesday-workingHours.pcap",
    "Thursday": "Thursday-WorkingHours.pcap",
    "Friday": "Friday-WorkingHours.pcap",
    "Sample": "wed_sample.pcap",
}
DEFAULT_DAYS = ["Tuesday", "Wednesday", "Thursday", "Friday"]   # Monday has no attacks
JVM_HEAP = "16g"
JOBS = 2                      # pcaps converted at the same time (one JVM each)
CHECK_ROWS = 200_000          # rows read per CSV for the value check
TIMEOUT_S = 6 * 3600

# This CICFlowMeter 4.0 build writes long column names; TRUST Lab files use the short ones.
# Same features, same order (checked on wed_sample 2026-10-31). Long name -> TRUST Lab name.
JAVA_CFM4_TO_TRUSTLAB = {
    "Total Fwd Packet": "Tot Fwd Pkts", "Total Bwd packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packet": "TotLen Fwd Pkts", "Total Length of Bwd Packet": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max", "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean", "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max", "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean", "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Flow Bytes/s": "Flow Byts/s", "Flow Packets/s": "Flow Pkts/s",
    "Fwd IAT Total": "Fwd IAT Tot", "Bwd IAT Total": "Bwd IAT Tot",
    "Fwd Header Length": "Fwd Header Len", "Bwd Header Length": "Bwd Header Len",
    "Fwd Packets/s": "Fwd Pkts/s", "Bwd Packets/s": "Bwd Pkts/s",
    "Packet Length Min": "Pkt Len Min", "Packet Length Max": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean", "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt", "SYN Flag Count": "SYN Flag Cnt", "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt", "ACK Flag Count": "ACK Flag Cnt", "URG Flag Count": "URG Flag Cnt",
    "CWR Flag Count": "CWE Flag Count", "ECE Flag Count": "ECE Flag Cnt",
    "Average Packet Size": "Pkt Size Avg",
    "Fwd Segment Size Avg": "Fwd Seg Size Avg", "Bwd Segment Size Avg": "Bwd Seg Size Avg",
    "Fwd Bytes/Bulk Avg": "Fwd Byts/b Avg", "Fwd Packet/Bulk Avg": "Fwd Pkts/b Avg",
    "Fwd Bulk Rate Avg": "Fwd Blk Rate Avg", "Bwd Bytes/Bulk Avg": "Bwd Byts/b Avg",
    "Bwd Packet/Bulk Avg": "Bwd Pkts/b Avg", "Bwd Bulk Rate Avg": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts", "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts", "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "FWD Init Win Bytes": "Init Fwd Win Byts", "Bwd Init Win Bytes": "Init Bwd Win Byts",
}


def trustlab_renames(header: list[str]) -> dict[str, str]:
    """{name in this CSV: TRUST Lab name} for long Java names and the CWR/CWE version alias."""
    from common.data import column_renames
    ren = {h: JAVA_CFM4_TO_TRUSTLAB[h] for h in header if h in JAVA_CFM4_TO_TRUSTLAB}
    ren.update({k: v for k, v in column_renames(header).items() if k not in ren and v not in ren.values()})
    return ren


# ---------------------------------------------------------------- conversion
def find_jnetpcap(extra: str | None) -> Path | None:
    """Folder that holds libjnetpcap.so (CICFlowMeter needs it to read pcaps)."""
    if extra:
        return Path(extra)
    roots = [CFM.parent.parent, Path("/home/abhinav_iot/tools/CICFlowMeter"), Path("/usr/lib"), Path("/usr/local/lib")]
    for root in roots:
        if root.exists():
            hits = sorted(root.rglob("libjnetpcap.so"))
            linux = [h for h in hits if "linux" in str(h).lower() or "native" in str(h).lower()] or hits
            if linux:
                return linux[0].parent
    return None


def convert(day: str, pcap: Path, out_dir: Path, log_dir: Path, heap: str, native: Path, log) -> dict:
    """Run cfm <pcap> <out_dir>. CICFlowMeter writes <pcap name>_Flow.csv into out_dir."""
    env = dict(os.environ, JAVA_OPTS=f"-Xmx{heap} -Djava.library.path={native}",
               LD_LIBRARY_PATH=f"{native}:{os.environ.get('LD_LIBRARY_PATH', '')}")
    t0 = time.time()
    log.info("[%s] converting %s (%.1f GB) ...", day, pcap.name, pcap.stat().st_size / 1e9)
    with open(log_dir / f"{day}.log", "w", encoding="utf-8") as f:
        r = subprocess.run([str(CFM), str(pcap), str(out_dir) + "/"], stdout=f, stderr=subprocess.STDOUT,
                           env=env, timeout=TIMEOUT_S, cwd=str(CFM.parent))
    csv = out_dir / f"{pcap.name}_Flow.csv"
    res = {"day": day, "pcap": str(pcap), "pcap_gb": pcap.stat().st_size / 1e9, "exit_code": r.returncode,
           "seconds": round(time.time() - t0, 1), "csv": str(csv), "csv_exists": csv.exists()}
    if csv.exists():
        res["csv_gb"] = csv.stat().st_size / 1e9
        with open(csv, "rb") as f:
            res["rows"] = sum(1 for _ in f) - 1
    log.info("[%s] exit %d, %.0f s, %s rows", day, r.returncode, res["seconds"], f"{res.get('rows', 0):,}")
    return res


# ---------------------------------------------------------------- column / value check
def check_columns(csv: Path) -> dict:
    """Compare a CICFlowMeter CSV with the 70 TRUST Lab model features."""
    import numpy as np
    import pandas as pd
    from common import config as C
    from common.data import extract_class, load_meta, read_header

    feats = load_meta()["features"]
    header = [h.strip() for h in read_header(csv)]
    rename = trustlab_renames(header)
    have = {rename.get(h, h) for h in header}
    missing = [f for f in feats if f not in have]
    tl_header = read_header(extract_class(C.BENIGN)[0])
    out = {"n_columns": len(header), "missing_model_features": missing,
           "extra_columns": [h for h in header if rename.get(h, h) not in set(tl_header)],
           "same_order_as_trustlab": [rename.get(h, h) for h in header if rename.get(h, h) in set(tl_header)]
           == [h for h in tl_header if h in {rename.get(x, x) for x in header}],
           "renamed": rename}
    if missing:
        return out

    # value check on the 13 window features + bulk features: CIC-IDS vs TRUST Lab Benign
    cols = [f for f in C.WINDOW_STAT_FEATURES + ["Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Bwd Byts/b Avg",
                                                 "Bwd Pkts/b Avg"] if f in feats]
    inv = {v: k for k, v in rename.items()}
    cic = pd.read_csv(csv, usecols=lambda c: c.strip() in {inv.get(f, f) for f in cols}, nrows=CHECK_ROWS)
    cic.columns = [rename.get(c.strip(), c.strip()) for c in cic.columns]
    tl = pd.read_csv(extract_class(C.BENIGN)[0], usecols=cols, nrows=CHECK_ROWS)
    stats = {}
    for f in cols:
        a = pd.to_numeric(cic[f], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        b = pd.to_numeric(tl[f], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        stats[f] = {"cic_median": float(a.median()) if len(a) else None,
                    "cic_p99": float(a.quantile(0.99)) if len(a) else None,
                    "cic_share_zero": float((a == 0).mean()) if len(a) else None,
                    "trustlab_median": float(b.median()) if len(b) else None,
                    "trustlab_p99": float(b.quantile(0.99)) if len(b) else None,
                    "trustlab_share_zero": float((b == 0).mean()) if len(b) else None}
    out["value_check"] = stats
    out["value_check_rows"] = int(len(cic))
    return out


def report(results: list[dict], checks: dict) -> str:
    L = ["# CIC-IDS2017 -> CICFlowMeter 4.0 (Java) flows: conversion and column check", "",
         "## 1. Conversion", "", "| Day | pcap (GB) | Exit code | Time (min) | Flows | CSV (GB) |",
         "|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['day']} | {r['pcap_gb']:.1f} | {r['exit_code']} | {r['seconds'] / 60:.1f} "
                 f"| {r.get('rows', 0):,} | {r.get('csv_gb', 0):.2f} |")
    L += ["", "## 2. Columns vs the 70 TRUST Lab model features", "",
          "| Day | Columns | Missing model features | Extra columns | Same order as TRUST Lab | Renamed |",
          "|---|---|---|---|---|---|"]
    for day, c in checks.items():
        if "error" in c:
            L.append(f"| {day} | – | check failed: {c['error']} | – | – | – |")
            continue
        miss = ", ".join(c["missing_model_features"]) or "none ✅"
        L.append(f"| {day} | {c['n_columns']} | {miss} | {', '.join(c['extra_columns']) or 'none'} "
                 f"| {'yes' if c['same_order_as_trustlab'] else 'no'} | {len(c['renamed'])} columns |")
    for day, c in checks.items():
        if "value_check" not in c:
            continue
        L += ["", f"## 3. Values: {day} vs TRUST Lab Benign (first {c['value_check_rows']:,} rows each)", "",
              "Large differences (for example a median 1000 times bigger, or a feature that is always 0 in one "
              "dataset) point to a unit or version difference.", "",
              "| Feature | CIC median | TL median | CIC p99 | TL p99 | CIC share 0 | TL share 0 |",
              "|---|---|---|---|---|---|---|"]
        for f, s in c["value_check"].items():
            L.append(f"| {f} | {wt.fmt(s['cic_median'], 'f1')} | {wt.fmt(s['trustlab_median'], 'f1')} "
                     f"| {wt.fmt(s['cic_p99'], 'f0')} | {wt.fmt(s['trustlab_p99'], 'f0')} "
                     f"| {wt.fmt(s['cic_share_zero'], 'pct')} | {wt.fmt(s['trustlab_share_zero'], 'pct')} |")
    L += ["", "## Notes", "",
          "- TRUST Lab Benign is normal traffic from another network, so values differ naturally; look for "
          "differences of units (x1000, x1e6) or features that are always 0 in only one dataset.",
          "- Next step: label these flows from the v3 CSVs (5-tuple + time), then test BAL_MS vs Suricata per day."]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="CIC-IDS2017 pcap -> CICFlowMeter 4.0 flows + column check")
    ap.add_argument("--days", nargs="+", default=None, choices=list(PCAPS), help=f"default {DEFAULT_DAYS}")
    ap.add_argument("--sample", action="store_true", help="only wed_sample.pcap (quick test)")
    ap.add_argument("--heap", default=JVM_HEAP, help="Java max heap per conversion, e.g. 16g")
    ap.add_argument("--jobs", type=int, default=JOBS, help="pcaps converted at the same time")
    ap.add_argument("--jnetpcap-dir", default=None, help="folder with libjnetpcap.so (default: search tools/)")
    args = ap.parse_args()
    days = ["Sample"] if args.sample else (args.days or DEFAULT_DAYS)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    flows_dir, log_dir = run_dir / "flows", run_dir / "cfm_logs"
    for d in (flows_dir, log_dir):
        d.mkdir(parents=True, exist_ok=False)
    log = wt.setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    results: list[dict] = []
    checks: dict = {}
    try:
        env = wt.log_environment(log)
        java = subprocess.run(["java", "-version"], capture_output=True, text=True)
        env["java"] = (java.stderr or java.stdout).splitlines()[0] if (java.stderr or java.stdout) else None
        log.info("java: %s", env["java"])
        if not CFM.exists():
            raise SystemExit(f"CICFlowMeter launcher not found: {CFM}")
        native = find_jnetpcap(args.jnetpcap_dir)
        if native is None or not (native / "libjnetpcap.so").exists():
            raise SystemExit("libjnetpcap.so not found under tools/ - give its folder with --jnetpcap-dir")
        env["jnetpcap_dir"] = str(native)
        log.info("jnetpcap native library: %s", native / "libjnetpcap.so")
        pcaps = {d: DATASET_DIR / PCAPS[d] for d in days}
        for d, p in pcaps.items():
            if not p.exists():
                raise SystemExit(f"{d}: pcap not found: {p}")
        free_gb = shutil.disk_usage(RUNS_DIR).free / 1e9
        config = {"script": SCRIPT_NAME, "days": days, "pcaps": {d: str(p) for d, p in pcaps.items()},
                  "cfm": str(CFM), "jvm_heap": args.heap, "jobs": args.jobs, "check_rows": CHECK_ROWS,
                  "free_disk_gb": round(free_gb), "environment": env}
        wt.write_json(run_dir / "config.json", config)
        log.info("settings: days %s, heap %s, %d at a time, %.0f GB free", days, args.heap, args.jobs, free_gb)

        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futs = [pool.submit(convert, d, p, flows_dir, log_dir, args.heap, native, log)
                    for d, p in pcaps.items()]
            results = [f.result() for f in futs]
        wt.write_json(run_dir / "results.json", {**out, "conversion": results})

        for r in results:
            if not r["csv_exists"]:
                checks[r["day"]] = {"error": f"no CSV (exit {r['exit_code']}, see cfm_logs/{r['day']}.log)"}
                continue
            try:
                checks[r["day"]] = check_columns(Path(r["csv"]))
                c = checks[r["day"]]
                log.info("[%s] columns %d | missing model features: %s | same order: %s",
                         r["day"], c["n_columns"], c["missing_model_features"] or "none",
                         c["same_order_as_trustlab"])
            except Exception as e:                                   # keep going for the other days
                checks[r["day"]] = {"error": f"{type(e).__name__}: {e}"}
                log.error("[%s] column check failed:\n%s", r["day"], traceback.format_exc())

        (run_dir / "COLUMN_CHECK.md").write_text(report(results, checks), encoding="utf-8")
        failed = [r["day"] for r in results if not r["csv_exists"] or r["exit_code"] != 0]
        bad_cols = [d for d, c in checks.items() if c.get("missing_model_features") or "error" in c]
        out.update({"conversion": results, "column_check": checks,
                    "status": "ok" if not failed and not bad_cols else "error",
                    "failed_days": failed, "days_with_column_problems": bad_cols})
        log.info("report: %s", run_dir / "COLUMN_CHECK.md")
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    wt.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.0f s)", out["time_taken_s"])
        return 0
    log.error("FINISHED WITH PROBLEMS: failed days %s, column problems %s",
              out.get("failed_days"), out.get("days_with_column_problems"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
