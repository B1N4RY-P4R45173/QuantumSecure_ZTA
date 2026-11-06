"""
Step 3 — Compare all models and decide which is best.

    python compare.py

Reads results/*.json (written by every MODEL folder and by MODEL SURICATA) and writes:
  * results/COMPARISON.md   — tables + decision, ready for your report
  * results/charts/*.png    — bar charts

Two separate decisions are made, because the system has two places:
  1. EDGE GATEWAY: must be fast, light, and able to block early   -> uses EDGE_WEIGHTS
  2. CONTROLLER (known-attack ML): must classify attacks well    -> uses CONTROLLER_WEIGHTS
A metric that was not measured for a model is shown as "n/m" and is left out of
that model's score (the remaining weights are re-balanced), so nothing is invented.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import config as C  # noqa: E402

# metric name -> (how to read it from a result, True if higher is better)
METRICS = {
    "binary_f1":         (lambda r: _get(r, "detection", "binary", "f1"), True),
    "detection_rate":    (lambda r: _get(r, "detection", "binary", "recall_detection_rate"), True),
    "fpr":               (lambda r: _get(r, "detection", "binary", "false_positive_rate"), False),
    "macro_f1":          (lambda r: _get(r, "detection", "macro_f1"), True),
    "bursts_detected":   (lambda r: _get(r, "detection", "time_to_detect", "bursts_detected_share"), True),
    "flows_before_alert": (lambda r: _get(r, "detection", "time_to_detect", "median_attack_flows_before_alert"), False),
    "packets_per_s":     (lambda r: _get(r, "performance", "equiv_packets_per_s"), True),
    "latency_ms":        (lambda r: _get(r, "performance", "latency_ms_single"), False),
    "peak_ram_mb":       (lambda r: _get(r, "performance", "peak_ram_mb"), False),
    "train_time_s":      (lambda r: _get(r, "performance", "train_time_s"), False),
    "early_block":       (lambda r: 1.0 if r.get("can_drop_first_packet") else 0.0, True),
}

# TODO(human): choose the weights for the EDGE decision (they must add up to 1.0).
# Think about what an inline gateway needs most: speed, early blocking, low RAM,
# few false alarms, or the best detection? The defaults below are only a starting point.
EDGE_WEIGHTS = {
    "packets_per_s": 0.25,
    "early_block": 0.20,
    "fpr": 0.15,
    "detection_rate": 0.15,
    "peak_ram_mb": 0.10,
    "latency_ms": 0.10,
    "train_time_s": 0.05,
}

CONTROLLER_WEIGHTS = {
    "macro_f1": 0.35,
    "binary_f1": 0.20,
    "fpr": 0.15,
    "bursts_detected": 0.10,
    "flows_before_alert": 0.10,
    "packets_per_s": 0.10,
}


def _get(d, *keys):
    for k in keys:
        if not isinstance(d, dict) or d.get(k) is None:
            return None
        d = d[k]
    return d


def load_results() -> dict[str, dict]:
    files = sorted(p for p in C.RESULTS_DIR.glob("*.json"))
    if not files:
        raise SystemExit(f"no results in {C.RESULTS_DIR} — train the models first")
    return {json.loads(p.read_text(encoding="utf-8"))["model"]: json.loads(p.read_text(encoding="utf-8"))
            for p in files}


def scores(results: dict[str, dict], weights: dict[str, float], models: list[str]) -> dict[str, dict]:
    """Min-max normalise every metric over `models` (best = 1, worst = 0), then weighted sum."""
    assert abs(sum(weights.values()) - 1.0) < 1e-6, f"weights must add up to 1.0: {weights}"
    out = {m: {"score": 0.0, "used_weight": 0.0, "missing": []} for m in models}
    for metric, w in weights.items():
        get, higher = METRICS[metric]
        vals = {m: get(results[m]) for m in models}
        known = {m: float(v) for m, v in vals.items() if v is not None}
        if metric in ("packets_per_s",):                       # spans orders of magnitude
            known = {m: float(np.log10(max(v, 1e-9))) for m, v in known.items()}
        lo, hi = (min(known.values()), max(known.values())) if known else (0, 0)
        for m in models:
            if m not in known:
                out[m]["missing"].append(metric)
                continue
            x = 1.0 if hi == lo else (known[m] - lo) / (hi - lo)
            out[m]["score"] += w * (x if higher else 1 - x)
            out[m]["used_weight"] += w
    for m in models:
        uw = out[m]["used_weight"]
        out[m]["score"] = out[m]["score"] / uw if uw else 0.0
    return out


def fmt(v, kind="f"):
    if v is None:
        return "n/m"
    if kind == "pct":
        return f"{100 * v:.2f}%"
    if kind == "int":
        return f"{v:,.0f}"
    if kind == "bool":
        return "yes" if v else "no"
    return f"{v:.4f}" if abs(v) < 100 else f"{v:,.0f}"


def charts(results: dict[str, dict]) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir = C.RESULTS_DIR / "charts"
    out_dir.mkdir(parents=True, exist_ok=True)
    made = []
    plots = [
        ("binary_f1", "Attack vs benign F1 (higher is better)", False),
        ("macro_f1", "Macro F1, 16 classes (higher is better)", False),
        ("fpr", "False positive rate (lower is better)", False),
        ("packets_per_s", "Packets per second, log scale (higher is better)", True),
        ("latency_ms", "Latency for one input, ms (lower is better)", False),
        ("peak_ram_mb", "Peak RAM, MB (lower is better)", False),
        ("flows_before_alert", "Median attack flows before first alert (lower is better)", False),
    ]
    for metric, title, log in plots:
        get = METRICS[metric][0]
        items = [(m, get(r)) for m, r in results.items() if get(r) is not None]
        if not items:
            continue
        fig, ax = plt.subplots(figsize=(7, 3.6))
        ax.bar([m for m, _ in items], [v for _, v in items], color="#4C78A8")
        if log:
            ax.set_yscale("log")
        ax.set_title(title, fontsize=11)
        ax.spines[["top", "right"]].set_visible(False)
        plt.xticks(rotation=20, ha="right")
        fig.tight_layout()
        path = out_dir / f"{metric}.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        made.append(path.name)
    return made


def main() -> None:
    results = load_results()
    names = list(results)
    ml = [m for m in names if m != "SURICATA"]
    lines = ["# Model comparison — known attacks (TRUST Lab)", ""]

    if any(r.get("quick_data") for r in results.values()):
        lines += ["> **WARNING:** some results come from `--quick` data. Use full data for the report.", ""]

    lines += ["## 1. Detection", "",
              "| Model | Input | Attack/benign F1 | Detection rate | False positive rate | Macro F1 (16 classes) "
              "| Bursts detected | Median attack flows before alert |",
              "|---|---|---|---|---|---|---|---|"]
    for m, r in results.items():
        g = lambda k: METRICS[k][0](r)  # noqa: E731
        lines.append(f"| {m} | {r.get('input', '')} | {fmt(g('binary_f1'))} | {fmt(g('detection_rate'), 'pct')} "
                     f"| {fmt(g('fpr'), 'pct')} | {fmt(g('macro_f1'))} | {fmt(g('bursts_detected'), 'pct')} "
                     f"| {fmt(g('flows_before_alert'))} |")

    lines += ["", "## 2. Edge fitness (speed and resources)", "",
              "| Model | Packets/s (equiv.) | Latency, one input (ms) | Peak RAM (MB) | Train time (s) "
              "| Waits for flow end? | Can block first packet? |",
              "|---|---|---|---|---|---|---|"]
    for m, r in results.items():
        g = lambda k: METRICS[k][0](r)  # noqa: E731
        lines.append(f"| {m} | {fmt(g('packets_per_s'), 'int')} | {fmt(g('latency_ms'))} | {fmt(g('peak_ram_mb'), 'int')} "
                     f"| {fmt(g('train_time_s'), 'int')} | {fmt(r.get('needs_flow_end'), 'bool')} "
                     f"| {fmt(r.get('can_drop_first_packet'), 'bool')} |")

    # per-class detection rate
    lines += ["", "## 3. Detection rate per attack class", "",
              "| Class | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for c in C.CLASSES[1:]:
        row = [fmt(_get(results[m], "detection", "per_class", c, "detection_rate"), "pct") for m in names]
        lines.append(f"| {c} | " + " | ".join(row) + " |")

    # decisions
    edge = scores(results, EDGE_WEIGHTS, names)
    ctrl = scores(results, CONTROLLER_WEIGHTS, ml) if ml else {}
    lines += ["", "## 4. Decision", "", "### Edge gateway (inline IPS)", "",
              "Weights: " + ", ".join(f"{k} {v:.2f}" for k, v in EDGE_WEIGHTS.items()), "",
              "| Rank | Model | Score (0–1) | Not measured |", "|---|---|---|---|"]
    for i, (m, s) in enumerate(sorted(edge.items(), key=lambda kv: -kv[1]["score"]), 1):
        lines.append(f"| {i} | {m} | {s['score']:.3f} | {', '.join(s['missing']) or '-'} |")
    if ctrl:
        lines += ["", "### Controller (known-attack ML model)", "",
                  "Weights: " + ", ".join(f"{k} {v:.2f}" for k, v in CONTROLLER_WEIGHTS.items()), "",
                  "| Rank | Model | Score (0–1) | Not measured |", "|---|---|---|---|"]
        for i, (m, s) in enumerate(sorted(ctrl.items(), key=lambda kv: -kv[1]["score"]), 1):
            lines.append(f"| {i} | {m} | {s['score']:.3f} | {', '.join(s['missing']) or '-'} |")

    best_edge = max(edge, key=lambda m: edge[m]["score"])
    lines += ["", f"**Best for the edge gateway:** {best_edge}"]
    if ctrl:
        lines.append(f"**Best ML model for the controller:** {max(ctrl, key=lambda m: ctrl[m]['score'])}")
    if "SURICATA" not in results:
        lines += ["", "> Suricata has no results yet. Run `MODEL SURICATA/run_suricata.py` (see its README)."]
    elif results["SURICATA"].get("detection") is None:
        lines += ["", "> Suricata detection was not measured (no labelled pcap). Its edge score uses speed, "
                      "RAM and early blocking only — say this clearly in the report."]

    made = charts(results)
    if made:
        lines += ["", "## 5. Charts", ""] + [f"![{c}](charts/{c})" for c in made]

    report = "\n".join(lines) + "\n"
    (C.RESULTS_DIR / "COMPARISON.md").write_text(report, encoding="utf-8")
    print(report)
    print(f"saved: {C.RESULTS_DIR / 'COMPARISON.md'}")


if __name__ == "__main__":
    main()
