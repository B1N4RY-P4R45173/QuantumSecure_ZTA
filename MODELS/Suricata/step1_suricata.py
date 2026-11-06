"""
Step 1 — Run real Suricata on one CIC-IDS2017 day (Linux / WSL only).

    python step1_suricata.py --day Wednesday --pcap data/pcap/Wednesday-workingHours.pcap

Saves output/<day>/suricata/: eve.json (alerts), perf.json (speed + RAM).
Run once per day; it takes a while on a 10+ GB pcap.

HOME_NET is set on the command line (--home-net), not taken from suricata.yaml. The default
yaml HOME_NET includes 172.16.0.0/12, which holds the CIC-IDS2017 attacker (172.16.0.1, the
NAT address of the attack network). Most ET rules only fire from $EXTERNAL_NET to $HOME_NET,
so with the default the attacker counts as "inside" and those rules stay silent.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import config as K

sys.path.insert(0, str(K.MODELS / "MODEL SURICATA"))
from run_suricata import packets_and_bytes, read_alerts, run_measured  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True, help="name for this run, e.g. Wednesday")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--rules", default="/var/lib/suricata/rules/suricata.rules")
    ap.add_argument("--config", default=None, help="suricata.yaml (default: system config)")
    ap.add_argument("--runmode", default="autofp", help="autofp = all cores, single = one core")
    ap.add_argument("--home-net", default="[192.168.10.0/24]",
                    help="HOME_NET for Suricata (default: the CIC-IDS2017 victim network)")
    args = ap.parse_args()

    if not shutil.which("suricata"):
        raise SystemExit("suricata not found — run setup_wsl.sh first (inside WSL Ubuntu)")
    pcap = Path(args.pcap).resolve()
    if not pcap.exists():
        raise SystemExit(f"pcap not found: {pcap}")
    out = K.OUT / args.day / "suricata"
    out.mkdir(parents=True, exist_ok=True)
    for old in ("eve.json", "fast.log", "stats.log", "suricata.log"):
        (out / old).unlink(missing_ok=True)          # Suricata appends; never mix two runs

    base = (["suricata", "-S", args.rules] + (["-c", args.config] if args.config else [])
            + ["--set", f"vars.address-groups.HOME_NET={args.home_net}"])
    print("1) startup only (loading rules) ...")
    startup_s, _, _ = run_measured(base + ["-T", "-l", str(out)])

    print(f"2) Suricata on {pcap.name} ({pcap.stat().st_size / 2**30:.1f} GB, runmode={args.runmode}) ...")
    total_s, peak_mb, log = run_measured(base + ["-r", str(pcap), "-l", str(out), "-k", "none",
                                                 "--runmode", args.runmode])
    (out / "stdout.log").write_text(log, encoding="utf-8")
    suri_log = out / "suricata.log"
    log_all = log + (suri_log.read_text(encoding="utf-8", errors="replace") if suri_log.exists() else "")
    pkts, byts = packets_and_bytes(log_all, out / "eve.json")
    engine_s = max(total_s - startup_s, 1e-9)
    n_alerts = len(read_alerts(out / "eve.json"))

    version = run_measured(["suricata", "-V"])[2].strip()
    perf = {
        "pcap": pcap.name, "runmode": args.runmode, "suricata_version": version,
        "rules_file": args.rules, "home_net": args.home_net, "packets": pkts, "bytes": byts, "alerts": n_alerts,
        "startup_s": startup_s, "engine_s": engine_s, "peak_ram_mb": peak_mb,
        "packets_per_s": pkts / engine_s, "mbit_per_s": byts * 8 / engine_s / 1e6,
    }
    (out / "perf.json").write_text(json.dumps(perf, indent=2), encoding="utf-8")
    print(f"   {pkts:,} packets, {n_alerts:,} alerts, {perf['packets_per_s']:,.0f} packets/s, "
          f"{perf['mbit_per_s']:,.0f} Mbit/s, peak RAM {peak_mb:,.0f} MB")
    print(f"saved: {out}")


if __name__ == "__main__":
    main()
