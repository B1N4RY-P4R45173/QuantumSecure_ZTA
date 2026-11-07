"""
ML Signal Extractor
-------------------
Scores a device's flows with the TRAINED detector and produces a per-device
summary for the trust scorer:

    { "10.0.0.9": {
        "flow_count":       150,
        "malicious_flows":  149,
        "anomaly_rate":     0.99,
        "top_class":        "Flood DoS/DDoS",
        "class_counts":     {"Scan / Recon": 94, "Spoofing / MITM": 55, ...},
        "ae_flagged":       150,
        "ae_rate":          1.0,
        "quarantine_hits":  65,
        "max_attack_probability": 0.997
      },
      ...
    }

This used to load a RandomForest fitted on 5,000 synthetic flows over 15
invented features - a placeholder, and the weakest link in the whole system,
because the trust score claimed an ML component that had never seen real
traffic. It now loads the actual research models from the final PC 2
evaluation (`MODELS/trained/`): LightGBM FLAT_cal for attack categories and
the autoencoder for traffic unlike anything normal. See detection/detector.py
for why neither lightgbm nor torch is imported to do it.

The input contract changed with the model, and deliberately was not papered
over: flows now carry the 39 CICIoT2023 features the model was trained on,
not the old 15. A file in the old shape will produce NaN-filled rows rather
than quietly scoring against mismatched columns, which is the failure worth
having.

    { "flows": [ {"src_ip": "10.0.0.9", "features": { <39 fields> }}, ... ] }

Still to come is the live feature extractor: these 39 features are built from
10-packet groups the way CIC's own pcap2csv does it, so a real deployment
needs that capture step at the Gateway. Until then the pipeline reads
recorded flows, and `Detector.inspect` is the seam that extractor will feed.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from detection.detector import load as load_detector

ROOT = Path(__file__).resolve().parents[1]


def score_flows(flows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    flows: [{"src_ip": str, "features": {feature_name: value, ...}}, ...]
    Returns a per-device aggregate.
    """
    if not flows:
        return {}

    detector = load_detector()

    by_device: dict[str, list[dict]] = defaultdict(list)
    for flow in flows:
        by_device[flow["src_ip"]].append(flow.get("features") or {})

    out: dict[str, dict[str, Any]] = {}
    for ip, rows in by_device.items():
        verdict = detector.inspect(rows)
        out[ip] = {
            "flow_count":       verdict.flow_count,
            "malicious_flows":  verdict.malicious_flows,
            "anomaly_rate":     verdict.anomaly_rate,
            "top_class":        verdict.top_class,
            "class_counts":     verdict.class_counts,
            "ae_flagged":       verdict.ae_flagged,
            "ae_rate":          verdict.ae_rate,
            "quarantine_hits":  verdict.quarantine_hits,
            "max_attack_probability": verdict.max_attack_probability,
        }
    return out


def extract(path: str | Path) -> dict[str, dict[str, Any]]:
    """Convenience: JSON file path -> per-device ML signal."""
    with Path(path).open("r", encoding="utf-8") as f:
        doc = json.load(f)
    return score_flows(doc.get("flows", []))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Score flows with the trained detector")
    ap.add_argument("path", help="path to a flows.json file")
    args = ap.parse_args()
    print(json.dumps(extract(args.path), indent=2))
