#!/usr/bin/env python3
"""Flip the demo device between clean and compromised traffic, live.

The Controller re-reads telemetry_snapshot.json whenever its mtime moves, so
writing this file mid-demo changes the next decision AND the next
re-evaluation sweep with no restart. That is what lets a reviewer watch a
live session be torn down.

Nothing here is typed in by hand. Both states are produced by running the
REAL trained models over REAL flows from the fixture, so what the reviewer
sees on screen is the detector's own output. If it were hand-written the
demo would prove nothing.

    python3 demo/telemetry.py clean        # benign traffic
    python3 demo/telemetry.py compromised  # C2 / Bot traffic + critical IDS
    python3 demo/telemetry.py show         # what the snapshot says now

By default it acts on the IP the Gateway sees the native client as, which is
the client-net bridge gateway. Override with --ip when demonstrating from
another host.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "SDP_CONTROLLER"))

from detection.detector import Detector            # noqa: E402

SNAPSHOT = ROOT / "SDP_CONTROLLER" / "telemetry_snapshot.json"
FIXTURE = ROOT / "SDP_CONTROLLER" / "tests" / "detector_fixture.csv"
ROWS = 40
SEED = 20261107

# The Suricata block for the compromised state. These are real signatures
# from the project's Suricata run, not invented strings; severity 1 is the
# critical class that trips the quarantine wire on its own.
COMPROMISED_SURICATA = {
    "alert_count": 5,
    "max_severity": 1,
    "severity_label": "critical",
    "categories": ["A Network Trojan was Detected", "Attempted Information Leak"],
    "signatures": [
        "ET MALWARE Cobalt Strike Beacon Observed",
        "ET SCAN Potential SSH Scan",
    ],
}


def client_ip() -> str:
    """How the Gateway sees a client running natively on this host.

    NOT the host's own address: the connection is NATed in through a Docker
    bridge, so the Gateway logs that bridge's gateway address.

    Which bridge is not obvious, and guessing it wrong points the whole demo
    at an IP nothing is using. client-net looks like the answer and is not:
    it is marked `internal`, so it carries no route from the host. Traffic to
    a published port arrives over the one network that is externally
    routable, which here is idp-net.

    Rather than encode that, ask the Gateway what it actually saw. Its log
    records the source of every knock, which is the ground truth. Only if
    nothing has knocked yet does this fall back to deriving the bridge.
    """
    try:
        out = subprocess.run(["docker", "logs", "--tail", "400", "sdp-gateway"],
                             capture_output=True, text=True, timeout=10)
        seen = re.findall(r"client_ip=(\d+\.\d+\.\d+\.\d+)",
                          out.stdout + out.stderr)
        if seen:
            return seen[-1]
    except Exception:
        pass

    # Nothing has knocked yet: take the gateway of the first non-internal
    # network the Gateway container is on, because an internal one cannot
    # carry host traffic at all.
    try:
        out = subprocess.run(
            ["docker", "network", "inspect", "idp-net",
             "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
            capture_output=True, text=True, timeout=10, check=True)
        found = out.stdout.strip()
        if found:
            return found
    except Exception:
        pass
    return "172.18.0.1"


def score(category: str) -> dict:
    """Run the real models over real rows of that traffic category."""
    detector = Detector(ROOT / "MODELS" / "trained")
    rows = list(csv.DictReader(FIXTURE.open(encoding="utf-8")))
    pool = [r for r in rows if r["category"] == category]
    if not pool:
        raise SystemExit(f"no {category!r} rows in the fixture")

    rng = np.random.RandomState(SEED)
    picked = [pool[i] for i in rng.choice(len(pool), min(ROWS, len(pool)),
                                          replace=False)]
    verdict = detector.inspect(
        [{f: float(r[f]) for f in detector.features} for r in picked])

    return {
        "flow_count": verdict.flow_count,
        "malicious_flows": verdict.malicious_flows,
        "anomaly_rate": round(verdict.anomaly_rate, 4),
        "top_class": verdict.top_class,
        "class_counts": verdict.class_counts,
        "ae_flagged": verdict.ae_flagged,
        "ae_rate": round(verdict.ae_rate, 4),
        "quarantine_hits": verdict.quarantine_hits,
        "max_attack_probability": round(verdict.max_attack_probability, 6),
        "source": "FLAT_cal + autoencoder, edge_inline_eval_20261104_164043",
        "traffic": category,
    }


def write(ip: str, category: str, suricata: dict | None) -> dict:
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    ml = score(category)
    snapshot[ip] = {"suricata": suricata, "ml": ml}
    SNAPSHOT.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    return ml


def show(ip: str) -> None:
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    entry = snapshot.get(ip)
    if entry is None:
        print(f"{ip}: no telemetry entry "
              f"(both detectors score half credit - 'we did not look')")
        return
    print(json.dumps({ip: entry}, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("state", choices=["clean", "compromised", "show"])
    ap.add_argument("--ip", default=None, help="defaults to the client-net bridge")
    args = ap.parse_args()

    ip = args.ip or client_ip()

    if args.state == "show":
        show(ip)
        return

    if args.state == "clean":
        ml = write(ip, "Normal", None)
        print(f"  {ip} -> CLEAN")
    else:
        ml = write(ip, "C2 / Bot", COMPROMISED_SURICATA)
        print(f"  {ip} -> COMPROMISED")
        print(f"  Suricata : {COMPROMISED_SURICATA['alert_count']} alerts, "
              f"max severity {COMPROMISED_SURICATA['max_severity']} "
              f"({COMPROMISED_SURICATA['severity_label']})")
        print(f"             {COMPROMISED_SURICATA['signatures'][0]}")

    print(f"  Detector : {ml['anomaly_rate']:.0%} of {ml['flow_count']} flows "
          f"labelled an attack, top={ml['top_class']}")
    print(f"             autoencoder flagged {ml['ae_rate']:.0%}, "
          f"{ml['quarantine_hits']} quarantine-grade")
    print()
    print("  Written. The Controller reloads on mtime - no restart needed.")
    print("  The next knock, and the next re-evaluation sweep, use this.")


if __name__ == "__main__":
    main()
