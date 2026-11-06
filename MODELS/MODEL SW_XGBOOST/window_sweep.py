"""
Window-size sweep for SW-XGBoost: train one model per window size and compare them.

    python "MODEL SW_XGBOOST/window_sweep.py"                       # windows 4 8 16 32 64 128
    python "MODEL SW_XGBOOST/window_sweep.py" --windows 8 16 32

Every window is trained exactly like MODEL SW_XGBOOST/train.py (same features, model
settings, class weights, early stopping on val). Two things are different on purpose:

  * Same rows for every window. A window of W flows can only score from row W-1 on,
    so every window is scored from row (largest W - 1) on. Otherwise the windows would
    be tested on slightly different flows.
  * The best window is chosen on VALIDATION F1, never on test. Choosing on test would
    tune the model to the test set, and its test score would no longer be honest.

Nothing in MODEL SW_XGBOOST/output or results/SW_XGBOOST.json is overwritten.
Saves:  MODEL SW_XGBOOST/window_sweep/w<W>/  (model.json, model_info.json, result.json)
        results/WINDOW_SWEEP.md and results/window_sweep.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common import config as C                                       # noqa: E402
from common.bench import PeakMemory, timed                           # noqa: E402
from common.data import load_meta, load_split                        # noqa: E402
from common.gbm import _class_weights, _make_model, _pick_device     # noqa: E402
from common.metrics import evaluate                                  # noqa: E402
from common.windows import sliding_window_features, targets          # noqa: E402

OUT = HERE / "window_sweep"
# the classes SW-XGBoost was weakest on with window 32
FOCUS = ["Slowloris", "DoS", "Bruteforce", "Exploitation", "PortScan", "BufferOverflow"]


def label(windows: tuple[int, ...]) -> str:
    return "+".join(map(str, windows))


def build(df, feats, windows: tuple[int, ...], start: int):
    """Window inputs, trimmed so the first scored row is `start` for every model.

    One window:  current flow + statistics of the last W flows.
    More windows (e.g. 8 and 64): current flow once, then the statistics of each window,
    so one model sees a short view and a long view of the traffic at the same time.
    """
    n_base = len(feats)
    cols, names = [], []
    for i, w in enumerate(windows):
        X, n = sliding_window_features(df, feats, w)
        X = X[start - (w - 1):]
        if i == 0:
            cols.append(X[:, :n_base]); names += n[:n_base]
        cols.append(X[:, n_base:])
        names += [f"W{w}_{x}" for x in n[n_base:]] if len(windows) > 1 else n[n_base:]
    y, burst = targets(df, windows[0])
    cut = start - (windows[0] - 1)
    return np.hstack(cols) if len(cols) > 1 else cols[0], y[cut:], burst[cut:], names


def train_one(windows: tuple[int, ...], start: int, splits: dict, feats: list[str], args, device: str) -> dict:
    perf: dict = {}
    with PeakMemory() as mem:
        data = {}
        for name, df in splits.items():
            with timed(perf, f"features_{name}_s"):
                data[name] = build(df, feats, windows, start)
        Xtr, ytr, _, names = data["train"]
        Xva, yva, _, _ = data["val"]
        Xte, yte, bte, _ = data["test"]

        present = np.unique(ytr)
        ytr_l = np.searchsorted(present, ytr)
        keep_va = np.isin(yva, present)
        model = _make_model("xgboost", len(present), args, device)
        print(f"   training on {len(Xtr):,} rows, {Xtr.shape[1]} features ...")
        with timed(perf, "train_time_s"):
            model.fit(Xtr, ytr_l, sample_weight=_class_weights(ytr_l),
                      eval_set=[(Xva[keep_va], np.searchsorted(present, yva[keep_va]))], verbose=False)
        model.set_params(device="cpu")                   # edge gateways have no GPU
        pred_va = present[model.predict(Xva).astype(int).ravel()]
        with timed(perf, "predict_test_s"):
            pred_te = present[model.predict(Xte).astype(int).ravel()]

    out_dir = OUT / ("w" + "_".join(map(str, windows)))
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_model(out_dir / "model.json")
    (out_dir / "model_info.json").write_text(json.dumps({
        "name": f"SW_XGBOOST_W{label(windows)}", "algo": "xgboost", "windowed": True,
        "window": windows[0] if len(windows) == 1 else list(windows),
        "model_file": "model.json", "base_features": feats,
        "classes": [C.CLASSES[i] for i in present],
    }, indent=2), encoding="utf-8")

    n = len(Xte)
    res = {
        "window": label(windows),
        "n_features": len(names),
        "val": evaluate(yva, pred_va),
        "test": evaluate(yte, pred_te, bte),
        "train_time_s": perf["train_time_s"],
        "train_device": device,
        "best_iteration": getattr(model, "best_iteration", None),
        "throughput_flows_per_s": n / (perf["features_test_s"] + perf["predict_test_s"]),
        "peak_ram_mb": mem.peak_mb,
        "model_size_mb": (out_dir / "model.json").stat().st_size / 2**20,
        "scored_from_row": start,
    }
    (out_dir / "result.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return res


def pct(v) -> str:
    return "–" if v is None else f"{100 * v:.2f}%"


def report(results: list[dict], best: int, start: int) -> str:
    L = ["# SW-XGBoost — window size sweep (TRUST Lab)", "",
         f"Every window is scored on the same test flows (from row {start}). "
         f"Best window chosen on **validation** F1: **{best} flows**.", "",
         "## 1. Detection (test set)", "",
         "| Window | Attack/benign F1 | Detection rate | False positive rate | Missed attacks | False alarms | Macro F1 (16 classes) | Val F1 |",
         "|---|---|---|---|---|---|---|---|"]
    for r in results:
        b, vb = r["test"]["binary"], r["val"]["binary"]
        mark = " ⭐" if r["window"] == best else ""
        L.append(f"| {r['window']}{mark} | {b['f1']:.4f} | {pct(b['recall_detection_rate'])} "
                 f"| {pct(b['false_positive_rate'])} | {b['fn']:,} | {b['fp']:,} "
                 f"| {r['test']['macro_f1']:.4f} | {vb['f1']:.4f} |")

    L += ["", "## 2. Weak classes (test set)", "",
          "Each cell: detected as an attack / given the right class.", "",
          "| Class | " + " | ".join(f"W={r['window']}" for r in results) + " |",
          "|---|" + "---|" * len(results)]
    for c in FOCUS:
        cells = []
        for r in results:
            pc = r["test"]["per_class"].get(c)
            cells.append("–" if pc is None else f"{pct(pc['detection_rate'])} / {pct(pc['recall'])}")
        L.append(f"| {c} | " + " | ".join(cells) + " |")

    L += ["", "## 3. Cost", "",
          "| Window | Features | Flows/s (CPU) | Peak RAM (MB) | Train time (s) | Trees used | Model size (MB) |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['window']} | {r['n_features']} | {r['throughput_flows_per_s']:,.0f} "
                 f"| {r['peak_ram_mb']:,.0f} | {r['train_time_s']:.0f} ({r['train_device']}) "
                 f"| {r['best_iteration']} | {r['model_size_mb']:.1f} |")

    L += ["", "## Notes", "",
          "- Missed attacks = attack flows predicted Benign. False alarms = Benign flows predicted as any attack.",
          "- Flows/s includes building the window features; it does not include CICFlowMeter.",
          "- Peak RAM covers building inputs for all three splits and training, not live use.",
          "- Choosing the window on test would make the test numbers too optimistic, so validation is used."]
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", type=int, nargs="+", default=[4, 8, 16, 32, 64, 128])
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=-1)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    args = ap.parse_args()
    args.gpu_id, args.gpu_platform = 0, 0               # only used by LightGBM

    windows = sorted(set(args.windows))
    if windows[0] < 2:
        raise SystemExit("window must be at least 2 flows")
    meta = load_meta()
    if meta["quick"]:
        print("WARNING: processed data is from --quick mode. Run preprocess.py for real results.")
    feats = meta["features"]
    start = windows[-1] - 1                              # first row every window can score
    device = _pick_device("xgboost", args)
    print(f"windows {windows}, training on {device.upper()}, every window scored from row {start}")

    splits = {name: load_split(name) for name in ("train", "val", "test")}
    results = []
    for w in windows:
        t0 = time.time()
        print(f"\n== window {w} ==")
        r = train_one((w,), start, splits, feats, args, device)
        b = r["test"]["binary"]
        print(f"   test F1 {b['f1']:.4f} | detection {pct(b['recall_detection_rate'])} | "
              f"false alarms {pct(b['false_positive_rate'])} | macro F1 {r['test']['macro_f1']:.4f} "
              f"| {time.time() - t0:.0f} s")
        results.append(r)

    best = max(results, key=lambda r: (r["val"]["binary"]["f1"], -r["val"]["binary"]["false_positive_rate"]))
    text = report(results, best["window"], start)
    C.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (C.RESULTS_DIR / "WINDOW_SWEEP.md").write_text(text, encoding="utf-8")
    (C.RESULTS_DIR / "window_sweep.json").write_text(
        json.dumps({"best_window_by_val_f1": best["window"], "results": results}, indent=2), encoding="utf-8")
    print("\n" + text)
    print(f"saved: {C.RESULTS_DIR / 'WINDOW_SWEEP.md'}")


if __name__ == "__main__":
    main()
