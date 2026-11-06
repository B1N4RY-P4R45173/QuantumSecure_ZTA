"""
Phase 3 (option A): CIC-IDS2017 pcaps -> flow CSVs with the PYTHON cicflowmeter.

Why Python and not Java: TRUST Lab packet lengths are full Ethernet frames (TCP Pkt Len Min = 54/60/66),
like the Python cicflowmeter. The Java CICFlowMeter 4.0 counts payload only (0 for 44% of flows).

Run it with the cfm-py environment (the only one with cicflowmeter):

    source /home/abhinav_iot/cfm-py/bin/activate
    python MODELS/Suricata/cicids_pyflows.py                       # Tuesday, Thursday, Friday
    python MODELS/Suricata/cicids_pyflows.py --days Wednesday      # redo Wednesday too, if wanted

Wednesday already exists: DataSet/wed_py/wed_py.csv (made earlier with the same tool).
DataSet/ is only READ. This is slow (hours per day); the days run in parallel.

Saves: runs/cicids_pyflows_<YYYYMMDD_HHMMSS>/
       run.log, config.json, results.json, flows/<Day>_py.csv, cfm_logs/<Day>.log
"""

from __future__ import annotations

import argparse
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
sys.path.insert(0, str(MODELS_DIR / "MODEL SW_XGBOOST"))

import window_tradeoff as wt                                           # noqa: E402  (logging helpers)

# ---------------------------------------------------------------- settings
DATASET_DIR = PROJECT_ROOT / "DataSet"
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "cicids_pyflows"
PCAPS = {
    "Monday": "Monday-WorkingHours.pcap",
    "Tuesday": "Tuesday-WorkingHours.pcap",
    "Wednesday": "Wednesday-workingHours.pcap",
    "Thursday": "Thursday-WorkingHours.pcap",
    "Friday": "Friday-WorkingHours.pcap",
}
DEFAULT_DAYS = ["Tuesday", "Thursday", "Friday"]
JOBS = 3                       # days converted at the same time (one process each)


def convert(day: str, pcap: Path, out_csv: Path, log_dir: Path, cfm: Path, log) -> dict:
    t0 = time.time()
    log.info("[%s] converting %s (%.1f GB) ... (this takes hours)", day, pcap.name, pcap.stat().st_size / 1e9)
    with open(log_dir / f"{day}.log", "w", encoding="utf-8") as f:
        r = subprocess.run([str(cfm), "-f", str(pcap), "-c", str(out_csv)], stdout=f, stderr=subprocess.STDOUT)
    res = {"day": day, "pcap": str(pcap), "exit_code": r.returncode, "minutes": round((time.time() - t0) / 60, 1),
           "csv": str(out_csv), "csv_exists": out_csv.exists()}
    if out_csv.exists():
        res["csv_gb"] = out_csv.stat().st_size / 1e9
        with open(out_csv, encoding="utf-8", errors="replace") as f:
            header = f.readline().strip().split(",")
            first = f.readline().strip().split(",")
            n = 1 + sum(1 for _ in f)
        res.update({"rows": n, "n_columns": len(header),
                    "timestamp_example": first[header.index("timestamp")] if "timestamp" in header else None})
    log.info("[%s] exit %d, %.0f min, %s flows, timestamp example: %s", day, r.returncode, res["minutes"],
             f"{res.get('rows', 0):,}", res.get("timestamp_example"))
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="CIC-IDS2017 pcap -> Python cicflowmeter flow CSVs")
    ap.add_argument("--days", nargs="+", default=DEFAULT_DAYS, choices=list(PCAPS))
    ap.add_argument("--jobs", type=int, default=JOBS)
    args = ap.parse_args()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    flows_dir, log_dir = run_dir / "flows", run_dir / "cfm_logs"
    for d in (flows_dir, log_dir):
        d.mkdir(parents=True, exist_ok=False)
    log = wt.setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    try:
        env = wt.log_environment(log)
        cfm = Path(sys.executable).parent / "cicflowmeter"
        if not cfm.exists():
            found = shutil.which("cicflowmeter")
            if not found:
                raise SystemExit("cicflowmeter not found: activate /home/abhinav_iot/cfm-py first")
            cfm = Path(found)
        env["cicflowmeter"] = str(cfm)
        log.info("cicflowmeter: %s", cfm)
        pcaps = {d: DATASET_DIR / PCAPS[d] for d in args.days}
        for d, p in pcaps.items():
            if not p.exists():
                raise SystemExit(f"{d}: pcap not found: {p}")
        wt.write_json(run_dir / "config.json", {"script": SCRIPT_NAME, "days": args.days, "jobs": args.jobs,
                                                "pcaps": {d: str(p) for d, p in pcaps.items()}, "environment": env})
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futs = [pool.submit(convert, d, p, flows_dir / f"{d}_py.csv", log_dir, cfm, log) for d, p in pcaps.items()]
            results = [f.result() for f in futs]
        failed = [r["day"] for r in results if r["exit_code"] != 0 or not r["csv_exists"] or not r.get("rows")]
        out.update({"status": "ok" if not failed else "error", "conversion": results, "failed_days": failed,
                    "flows_dir": str(flows_dir)})
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    wt.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.0f min)", out["time_taken_s"] / 60)
        return 0
    log.error("FINISHED WITH PROBLEMS: %s", out.get("failed_days") or "see error above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
