"""
Single-window vs two-window SW-XGBoost, trained and tested in one run.

    python "MODEL SW_XGBOOST/compare_windows.py"                    # 8, 32, 64 and 8+64
    python "MODEL SW_XGBOOST/compare_windows.py" --models 32 8+64 16+64

A model is written as its window sizes: "32" = one window of 32 flows,
"8+64" = one model that sees the last 8 flows AND the last 64 flows.

Same rules as window_sweep.py: same training settings, every model scored on the
same test flows, and the best model chosen on VALIDATION F1, never on test.

Saves:  MODEL SW_XGBOOST/window_sweep/w<sizes>/   (one folder per model)
        results/WINDOW_COMPARISON.md and results/window_comparison.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from common import config as C                     # noqa: E402
from common.data import load_meta, load_split      # noqa: E402
from common.gbm import _pick_device                # noqa: E402
from window_sweep import label, pct, train_one     # noqa: E402


def parse(spec: str) -> tuple[int, ...]:
    windows = tuple(sorted({int(w) for w in spec.split("+")}))
    if windows[0] < 2:
        raise SystemExit(f"{spec}: window must be at least 2 flows")
    return windows


def report(results: list[dict], best: str, start: int) -> str:
    attacks = [c for c in C.CLASSES if c != C.BENIGN and c in results[0]["test"]["per_class"]]
    L = ["# SW-XGBoost — single window vs two windows (TRUST Lab)", "",
         f"All models trained the same way and scored on the same test flows (from row {start}).",
         f"Best model chosen on **validation** F1: **{best}**.", "",
         "Model name = window sizes. `32` = one window of 32 flows. "
         "`8+64` = one model that sees the last 8 flows and the last 64 flows.", "",
         "## 1. Attack vs normal (test set)", "",
         "| Model | F1 | Detection rate | False alarm rate | Missed attacks | False alarms | Macro F1 (16 classes) | Val F1 |",
         "|---|---|---|---|---|---|---|---|"]
    for r in results:
        b = r["test"]["binary"]
        mark = " ⭐" if r["window"] == best else ""
        L.append(f"| {r['window']}{mark} | {b['f1']:.4f} | {pct(b['recall_detection_rate'])} "
                 f"| {pct(b['false_positive_rate'])} | {b['fn']:,} | {b['fp']:,} "
                 f"| {r['test']['macro_f1']:.4f} | {r['val']['binary']['f1']:.4f} |")

    for title, key, note in [
        ("2. Detected as an attack, per class (test set)", "detection_rate",
         "Share of each attack's flows flagged as any attack. **Bold** = best in the row."),
        ("3. Given the right attack name, per class (test set)", "recall",
         "Share of each attack's flows given its own class name. **Bold** = best in the row."),
    ]:
        L += ["", f"## {title}", "", note, "",
              "| Class | " + " | ".join(r["window"] for r in results) + " |",
              "|---|" + "---|" * len(results)]
        for c in attacks:
            vals = [r["test"]["per_class"][c][key] for r in results]
            top = max(vals)
            cells = [f"**{pct(v)}**" if v == top and vals.count(top) < len(vals) else pct(v) for v in vals]
            L.append(f"| {c} | " + " | ".join(cells) + " |")

    L += ["", "## 4. Cost", "",
          "| Model | Features | Flows/s (CPU) | Peak RAM (MB) | Train time (s) | Trees used | Model size (MB) |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['window']} | {r['n_features']} | {r['throughput_flows_per_s']:,.0f} "
                 f"| {r['peak_ram_mb']:,.0f} | {r['train_time_s']:.0f} ({r['train_device']}) "
                 f"| {r['best_iteration']} | {r['model_size_mb']:.1f} |")

    L += ["", "## Notes", "",
          "- Missed attacks = attack flows predicted Benign. False alarms = Benign flows predicted as any attack.",
          "- Flows/s includes building the window features; it does not include CICFlowMeter.",
          "- Peak RAM covers building inputs for all three splits and training, not live use.",
          "- GPU training is not exactly repeatable, so very small differences between models are noise."]
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["8", "32", "64", "8+64"])
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=-1)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    args = ap.parse_args()
    args.gpu_id, args.gpu_platform = 0, 0

    models = [parse(m) for m in args.models]
    meta = load_meta()
    feats = meta["features"]
    start = max(max(m) for m in models) - 1
    device = _pick_device("xgboost", args)
    print(f"models {[label(m) for m in models]}, training on {device.upper()}, scored from row {start}")

    splits = {name: load_split(name) for name in ("train", "val", "test")}
    results = []
    for m in models:
        t0 = time.time()
        print(f"\n== model {label(m)} ==")
        r = train_one(m, start, splits, feats, args, device)
        b = r["test"]["binary"]
        print(f"   test F1 {b['f1']:.4f} | detection {pct(b['recall_detection_rate'])} | "
              f"false alarms {pct(b['false_positive_rate'])} | macro F1 {r['test']['macro_f1']:.4f} "
              f"| {time.time() - t0:.0f} s")
        results.append(r)

    best = max(results, key=lambda r: (r["val"]["binary"]["f1"], -r["val"]["binary"]["false_positive_rate"]))
    text = report(results, best["window"], start)
    C.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (C.RESULTS_DIR / "WINDOW_COMPARISON.md").write_text(text, encoding="utf-8")
    (C.RESULTS_DIR / "window_comparison.json").write_text(
        json.dumps({"best_by_val_f1": best["window"], "results": results}, indent=2), encoding="utf-8")
    print("\n" + text)
    print(f"saved: {C.RESULTS_DIR / 'WINDOW_COMPARISON.md'}")


if __name__ == "__main__":
    main()
