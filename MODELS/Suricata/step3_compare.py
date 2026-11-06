"""
Step 3 — Compare Suricata and XGBoost on the same test flows.

    python step3_compare.py --day Wednesday

Needs: output/<day>/suricata/ (step 1) and output/<day>/flows.parquet + xgb_* (step 2).
Writes output/<day>/COMPARISON.md and comparison.json.

How a flow counts as "detected by Suricata":
  at least one Suricata alert with the same protocol + both IP:port pairs (either direction),
  whose time falls inside the flow (CSV start time .. start + duration + 60 s, ± tolerance).
  The +60 s is because CIC-IDS2017 times have minutes only.

Two Suricata versions are reported:
  * SURICATA_ALL      : every alert counts
  * SURICATA_THREATS  : engine/protocol events ("SURICATA ...") and informational rules
                        ("ET INFO", "ET POLICY") are ignored — these are not attack signatures
On CIC-IDS2017 almost every engine event is "SURICATA TCPv4 invalid checksum", an artefact of
how the traffic was captured. SURICATA_ALL is kept for transparency; SURICATA_THREATS is the
Suricata result to report.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

import numpy as np
import pandas as pd

import config as K

sys.path.insert(0, str(K.MODELS / "MODEL SURICATA"))
sys.path.insert(0, str(K.MODELS))
from common.metrics import binary_metrics, time_to_detect  # noqa: E402
from run_suricata import read_alerts                        # noqa: E402

NON_THREAT = re.compile(r"^(SURICATA |ET INFO|ET POLICY)")
SMALL_LABEL = 30          # fewer test flows than this: percentages are not reliable


def endpoint_keys(proto, ip1, port1, ip2, port2) -> pd.Series:
    """Same key for both directions: 'proto|smaller endpoint|bigger endpoint'."""
    e1 = ip1.astype(str) + ":" + port1.astype(str)
    e2 = ip2.astype(str) + ":" + port2.astype(str)
    lo = np.where(e1 < e2, e1, e2)
    hi = np.where(e1 < e2, e2, e1)
    return proto.astype(str) + "|" + pd.Series(lo, index=e1.index) + "|" + pd.Series(hi, index=e1.index)


def build_pairs(flows: pd.DataFrame, alerts: pd.DataFrame) -> pd.DataFrame:
    """All (flow, alert) pairs that share the same endpoints — time is checked later."""
    fk = endpoint_keys(flows["Protocol"], flows["Source IP"], flows["Source Port"],
                       flows["Destination IP"], flows["Destination Port"])
    a_ip = alerts["a"].map(lambda t: t[0]); a_port = alerts["a"].map(lambda t: int(t[1] or 0))
    b_ip = alerts["b"].map(lambda t: t[0]); b_port = alerts["b"].map(lambda t: int(t[1] or 0))
    ak = endpoint_keys(alerts["proto"], a_ip, a_port, b_ip, b_port)
    f = pd.DataFrame({"key": fk, "flow": flows.index, "tod": flows["tod"].to_numpy(),
                      "dur": flows["Flow Duration"].to_numpy() / 1e6})
    a = pd.DataFrame({"key": ak, "ts": alerts["ts"].to_numpy(), "threat": alerts["threat"].to_numpy()})
    return f.merge(a, on="key", how="inner")


def matched_flows(pairs: pd.DataFrame, offset_h: int, tol: float, threats_only: bool) -> set:
    tod_alert = (pairs["ts"] + offset_h * 3600) % 86400
    ok = (tod_alert >= pairs["tod"] - tol) & (tod_alert <= pairs["tod"] + pairs["dur"] + 60 + tol)
    if threats_only:
        ok &= pairs["threat"]
    return set(pairs.loc[ok, "flow"])


def calibrate_offset(pairs: pd.DataFrame, tol: float) -> tuple[int, dict]:
    """Try every whole-hour offset (UTC -> CSV local time); keep the one that matches most flows.
    Uses no labels, so it cannot favour any detector."""
    counts = {h: len(matched_flows(pairs, h, tol, False)) for h in range(-12, 13)}
    best = max(counts, key=counts.get)
    return best, counts


def detector_metrics(test: pd.DataFrame, flagged: np.ndarray) -> dict:
    y = test["is_attack"].to_numpy()
    p = flagged.astype(np.int64)
    labels = test["Label"].to_numpy()
    change = np.r_[True, labels[1:] != labels[:-1]]
    burst = np.where(y == 1, np.cumsum(change), -1)
    per_label = (pd.DataFrame({"Label": labels, "flag": p}).groupby("Label")["flag"]
                 .agg(["mean", "size"]).rename(columns={"mean": "flagged_share", "size": "flows"}))
    return {
        "binary": binary_metrics(y, p),
        "per_label": per_label.to_dict(orient="index"),
        "time_to_detect": time_to_detect(p, burst),
    }


def fmt_pct(v):
    return "n/m" if v is None else f"{100 * v:.2f}%"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--tolerance", type=float, default=120.0, help="seconds")
    ap.add_argument("--offset-hours", type=int, default=None,
                    help="UTC -> CSV time offset; default: find it automatically")
    args = ap.parse_args()
    day = K.OUT / args.day

    flows = pd.read_parquet(day / "flows.parquet")
    preds = pd.read_parquet(day / "xgb_predictions.parquet")
    xperf = json.loads((day / "xgb_perf.json").read_text(encoding="utf-8"))
    sperf = json.loads((day / "suricata" / "perf.json").read_text(encoding="utf-8"))
    alerts = read_alerts(day / "suricata" / "eve.json")
    if alerts.empty:
        alerts = pd.DataFrame(columns=["ts", "proto", "a", "b", "signature", "category"])
    alerts["threat"] = ~alerts["signature"].fillna("").str.match(NON_THREAT)
    print(f"{len(flows):,} flows, {len(alerts):,} Suricata alerts "
          f"({int(alerts['threat'].sum()):,} threat alerts)")

    pairs = build_pairs(flows, alerts)
    if args.offset_hours is None:
        offset, table = calibrate_offset(pairs, args.tolerance)
        print(f"time offset: {offset:+d} h (flows matched per offset: "
              + ", ".join(f"{h:+d}:{n}" for h, n in table.items() if n) + ")")
    else:
        offset, table = args.offset_hours, {}

    test = flows[flows["split"] == "test"]
    hit_all = matched_flows(pairs, offset, args.tolerance, False)
    hit_thr = matched_flows(pairs, offset, args.tolerance, True)
    detectors = {
        "SURICATA_ALL": test.index.isin(list(hit_all)),
        "SURICATA_THREATS": test.index.isin(list(hit_thr)),
    }
    # ML detectors: prediction column -> the name that means "benign" for that model
    for col, benign in [("xgb_retrained", "BENIGN"), ("sw_xgb_retrained", "BENIGN"),
                        ("xgb_trustlab", "Benign"), ("sw_xgb_trustlab", "Benign")]:
        if col in preds:
            detectors[col.upper()] = (preds.loc[test.index, col] != benign).to_numpy()
    res = {name: detector_metrics(test, flag) for name, flag in detectors.items()}

    n_flows_with_alert = len(hit_all)          # sanity check: should not be ~0
    pkts_per_flow = float((test["Total Fwd Packets"] + test["Total Backward Packets"]).mean())

    # ------------------------------------------------------------------ report
    L = [f"# XGBoost vs Suricata — CIC-IDS2017 {args.day}", "",
         f"Test flows: {len(test):,} ({int(test['is_attack'].sum()):,} attack). "
         f"Suricata: {sperf['suricata_version']}, rules `{sperf['rules_file']}`, runmode {sperf['runmode']}, "
         f"HOME_NET `{sperf.get('home_net', 'suricata.yaml default')}`. "
         f"Time offset UTC→CSV: {offset:+d} h. Flows with any alert (all splits): {n_flows_with_alert:,}.", "",
         "## 1. Detection (attack vs benign)", "",
         "| Detector | Detection rate | False positive rate | Precision | F1 | Attack bursts detected | Median attack flows before alert |",
         "|---|---|---|---|---|---|---|"]
    for n, r in res.items():
        b, t = r["binary"], r["time_to_detect"]
        L.append(f"| {n} | {fmt_pct(b['recall_detection_rate'])} | {fmt_pct(b['false_positive_rate'])} "
                 f"| {fmt_pct(b['precision'])} | {b['f1']:.4f} | {fmt_pct(t['bursts_detected_share'])} "
                 f"| {t['median_attack_flows_before_alert']} |")

    L += ["", "## 2. Share of flows flagged, per CIC-IDS2017 label", "",
          "For attacks this is the detection rate; for BENIGN it is the false alarm rate.", "",
          "| Label | Flows | " + " | ".join(res) + " |", "|---|---|" + "---|" * len(res)]
    for lab in sorted(test["Label"].unique(), key=lambda s: (s != "BENIGN", s)):
        cells = [fmt_pct(res[n]["per_label"].get(lab, {}).get("flagged_share")) for n in res]
        L.append(f"| {lab} | {int((test['Label'] == lab).sum()):,} | " + " | ".join(cells) + " |")

    L += ["", "## 3. Speed and resources (all measured on CPU)", "",
          "| Detector | Packets/s | Flows/s | Waits for | Latency, one input | Peak RAM (MB) | Startup / training |",
          "|---|---|---|---|---|---|---|",
          f"| Suricata | {sperf['packets_per_s']:,.0f} ({sperf['mbit_per_s']:,.0f} Mbit/s) | – | nothing (per packet) "
          f"| inline | {sperf['peak_ram_mb']:,.0f} | {sperf['startup_s']:.1f} s rule loading |"]
    for name, xp in xperf.items():
        wait = "end of flow" if xp.get("window_flows", 1) == 1 else f"end of flow + last {xp['window_flows']} flows"
        lat = f"{xp['latency_ms_single']:.3f} ms" if "latency_ms_single" in xp else "–"
        trained = (f"{xp['train_time_s']:.0f} s on {xp['train_device']}" if "train_time_s" in xp
                   else "trained on TRUST Lab")
        L.append(f"| {name} | {xp['throughput_flows_per_s'] * pkts_per_flow:,.0f} (equiv.) "
                 f"| {xp['throughput_flows_per_s']:,.0f} | {wait} | {lat} | {xp['peak_ram_mb']:,.0f} | {trained} |")
    L += ["", "XGBoost speed does **not** include CICFlowMeter (turning packets into flows). "
          "Suricata speed includes all packet work. So the XGBoost numbers are optimistic.",
          "", "## 4. Design differences", "",
          "| | Suricata | XGBoost |", "|---|---|---|",
          "| Input | Packets | Finished flows (CICFlowMeter) |",
          "| Can block the first packet of an attack | Yes (inline IPS mode) | No — waits for the flow to end |",
          "| Explains an alert | Rule name, SID, often a CVE | Class + probability |",
          "| Adding a new known attack | Write/update a rule (minutes) | Collect labelled data and retrain |",
          "| Needs training data | No | Yes |"]

    if len(alerts):
        top = alerts["signature"].value_counts().head(15)
        L += ["", "## 5. Top Suricata signatures", "", "| Signature | Alerts | Counted as threat |", "|---|---|---|"]
        L += [f"| {s} | {c:,} | {'no' if NON_THREAT.match(str(s)) else 'yes'} |" for s, c in top.items()]

    checksum = int(alerts["signature"].fillna("").str.contains("invalid checksum").sum())
    small = [f"{lab} ({n})" for lab, n in test["Label"].value_counts().items() if n < SMALL_LABEL]
    L += ["", "## 6. Limits", ""]
    if len(alerts) and checksum / len(alerts) > 0.5:
        L.append(f"- **Use SURICATA_THREATS, not SURICATA_ALL.** {checksum:,} of {len(alerts):,} alerts "
                 f"({checksum / len(alerts):.0%}) are \"invalid checksum\" engine events, an artefact of how "
                 "CIC-IDS2017 was captured, not attacks. They inflate both detection and false alarms of SURICATA_ALL.")
    if "home_net" not in sperf:
        L.append("- **HOME_NET was not set** (old step 1 run). The default includes the attacker 172.16.0.1, "
                 "so most ET rules could not fire. Rerun step 1.")
    if small:
        L.append(f"- Too few test flows for reliable percentages: {', '.join(small)}.")
    L += [
          "- ML peak RAM includes holding the whole day in pandas; a live detector scoring one flow at a time needs less.",
          "- *_TRUSTLAB models were trained on a built TRUST Lab stream (attack bursts inserted into benign traffic). "
          "Real CIC-IDS2017 traffic is mixed differently, so the sliding-window statistics shift; this hits SW models hardest.",
          "- CIC-IDS2017 has known label and flow errors (Engelen et al., 2021). Some \"false positives\" may be real attacks with wrong labels, and the reverse.",
          "- CSV times have minutes only, so matching uses a time tolerance; a few matches can be wrong.",
          "- Suricata is scored on the test flows only, so it is compared with XGBoost on exactly the same flows.",
          "- Train/test use 10-minute time blocks (3 train : 2 test), so overlapping windows do not leak. "
          "An attack that happens only inside test blocks is never seen by the *_RETRAINED models.",
          "- *_RETRAINED models learn from this same day (home advantage). *_TRUSTLAB models and Suricata "
          "were not trained on CIC-IDS2017, so that comparison is the fairest.",
          "- Suricata rules are newer than 2017. Rules written after an attack became public make Suricata look better than on day one."]
    report = "\n".join(L) + "\n"
    (day / "COMPARISON.md").write_text(report, encoding="utf-8")
    (day / "comparison.json").write_text(json.dumps({
        "offset_hours": offset, "offset_table": table, "detectors": res,
        "suricata_perf": sperf, "xgb_perf": xperf, "avg_packets_per_flow": pkts_per_flow,
    }, indent=2, default=str), encoding="utf-8")
    print(report)
    print(f"saved: {day / 'COMPARISON.md'}")


if __name__ == "__main__":
    main()
