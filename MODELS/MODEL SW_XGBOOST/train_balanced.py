"""
BALANCED detector: equal importance for SINGLE attacks and TIME-SERIES attacks.

    python "MODELS/MODEL SW_XGBOOST/train_balanced.py"            # full run
    python "MODELS/MODEL SW_XGBOOST/train_balanced.py" --quick    # code check (20 trees)
    python "MODELS/MODEL SW_XGBOOST/train_balanced.py" --algo lightgbm   # same study with LightGBM
                                                                  # -> runs/sw_lgbm_balanced_<ts>/

Problem (runs/sw_xgb_window_tradeoff_*): a bigger window classifies floods/scans better and
gives fewer false alarms, but misses attacks hidden among normal flows. Plain XGBoost is the
opposite. This script tries three fixes together and keeps the best on VALIDATION:

  1. Solo + burst training stream (from train_solo.py): attacks also appear ALONE, so the
     model cannot learn "an attack always comes in a group".
  2. Deviation features: how far the current flow is from its window average. A lone
     attack stands out instead of being averaged away.
  3. Multi-scale window: one short window (sees single attacks) + one long window
     (sees time-series attacks) in the same model.
  4. Safety-net ensemble: plain XGBoost runs next to the best balanced model and can
     only ADD an alert when it is very sure. Its threshold is tuned on validation so
     false alarms stay inside a budget.

Models:
  FLAT          plain XGBoost, 1 flow                 (original stream)
  SW_W16        SW-XGBoost window 16                  (original stream, reference)
  BAL_W16       window 16 + deviation                 (solo + burst stream)
  BAL_MS        windows SHORT + LONG + deviation      (solo + burst stream)
  ENS           best BAL + FLAT safety net            (threshold tuned on validation)

Choice = highest BALANCE SCORE on validation = harmonic mean of
  hidden single-attack detection, single-flow attacks right class, time-series attacks right class,
with false alarms not above the --fpr-budget compared with the best BAL model.

Test sets: TEST_ORIGINAL (data/processed/test.parquet, unchanged) and TEST_SOLO (the same
test flows, arranged with many solo attacks).

Saves: runs/sw_xgb_balanced_<YYYYMMDD_HHMMSS>/
       run.log, config.json, results.json, BALANCED.md, charts/*.png, models/<name>/
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import window_tradeoff as wt                                   # noqa: E402  (logging, scoring, colors)

# ---------------------------------------------------------------- settings
RUNS_DIR = wt.RUNS_DIR
SCRIPT_NAME = "sw_xgb_balanced"
SHORT_WINDOW = 8
MID_WINDOW = 16
LONG_WINDOW = 56
SOLO_SHARE = 0.10        # share of each single-flow attack class put in as solo units (train/val)
OTHER_SHARE = 0.03       # share of every other attack class put in as solo units
SOLO_GAP = 32            # at least 32 normal flows around each solo unit
TEST_SOLO_SHARE = 0.08   # solo share of every class in TEST_SOLO (same as train_solo.py)
FPR_BUDGET = 0.002       # ensemble may add at most 0.2 percentage points of false alarms (validation)
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.97, 0.98, 0.99, 0.995, 0.999]

SPECS = {
    "FLAT": {"windows": [], "dev": None, "stream": "original"},
    "SW_W16": {"windows": [MID_WINDOW], "dev": None, "stream": "original"},
    "BAL_W16": {"windows": [MID_WINDOW], "dev": MID_WINDOW, "stream": "solo"},
    "BAL_MS": {"windows": [SHORT_WINDOW, LONG_WINDOW], "dev": SHORT_WINDOW, "stream": "solo"},
}
CHART_FILES = ["01_balance_test_original.png", "02_balance_test_solo.png", "03_iot_cost.png"]


# ---------------------------------------------------------------- inputs
def first_row(specs: dict) -> int:
    """First row every model can score (also leaves room for the 32-flow context check)."""
    ws = [w for s in specs.values() for w in s["windows"]] + [wt.REF_WINDOW]
    return max(ws) - 1


def build_X(df, feats: list[str], spec: dict, start: int) -> np.ndarray:
    """Inputs from row `start` on: current flow + stats of each window (+ deviation)."""
    from common.windows import sliding_window_features
    from train_solo import deviation_features
    if not spec["windows"]:
        return df[feats].to_numpy(np.float32)[start:]
    cols = []
    for i, w in enumerate(spec["windows"]):
        X, _ = sliding_window_features(df, feats, w)
        X = X[start - (w - 1):]
        cols.append(X if i == 0 else X[:, len(feats):])     # current flow only once
    if spec["dev"]:
        d = spec["dev"]
        D, _ = deviation_features(df, d)
        cols.append(D[start - (d - 1):])
    return np.hstack(cols) if len(cols) > 1 else cols[0]


def targets(df, start: int):
    y = df["label"].to_numpy(np.int64)[start:]
    burst = df["burst"].to_numpy(np.int64)[start:]
    kind = df["unit_kind"].to_numpy()[start:] if "unit_kind" in df else np.zeros(len(y), np.int8)
    return y, burst, kind


def masks_for(df, start: int) -> dict:
    m = wt.context_masks(df, start)
    _, _, kind = targets(df, start)
    m["solo"] = kind == 2
    return m


# ---------------------------------------------------------------- scoring
def score(y, pred, burst, masks) -> dict:
    out = wt.score(y, pred, burst, {k: masks[k] for k in ("hidden", "start", "busy")})
    hit = pred != BENIGN_ID()
    out["solo_unit_detection"] = float(hit[masks["solo"]].mean()) if masks["solo"].any() else None
    parts = [out["hidden_detection"], out["point_right_class"], out["series_right_class"]]
    parts = [p for p in parts if p is not None]
    out["balance_score"] = float(len(parts) / sum(1 / max(p, 1e-9) for p in parts)) if parts else None
    return out


def BENIGN_ID() -> int:
    from common import config as C
    return C.CLASS_TO_ID[C.BENIGN]


def combine(p_bal, ids_bal, p_flat, ids_flat, threshold: float) -> np.ndarray:
    """BAL decides; FLAT may only ADD an alert where BAL says normal and FLAT is sure it is an attack."""
    B = BENIGN_ID()
    pred = ids_bal[p_bal.argmax(1)]
    b_col = int(np.where(ids_flat == B)[0][0])
    flat_attack_p = 1.0 - p_flat[:, b_col]
    p = p_flat.copy()
    p[:, b_col] = -1
    flat_cls = ids_flat[p.argmax(1)]
    add = (pred == B) & (flat_attack_p >= threshold)
    pred = pred.copy()
    pred[add] = flat_cls[add]
    return pred


# ---------------------------------------------------------------- training
def train(name: str, spec: dict, data: dict, args, device: str, run_dir: Path, log) -> tuple:
    from common import config as C
    from common.bench import PeakMemory, timed
    from common.gbm import _class_weights, _make_model
    perf: dict = {}
    with PeakMemory() as mem:
        Xtr, ytr = data["train"]["X"][name], data["train"]["y"]
        Xva, yva = data["val"]["X"][name], data["val"]["y"]
        present = np.unique(ytr)
        ytr_l = np.searchsorted(present, ytr)
        keep = np.isin(yva, present)
        model = _make_model(wt.ALGO, len(present), args, device)
        log.info("[%s] training %s on %s rows, %d features (%s stream, %s) ...",
                 name, wt.ALGO, f"{len(Xtr):,}", Xtr.shape[1], spec["stream"], device)
        with timed(perf, "train_time_s"):
            wt.fit_model(model, Xtr, ytr_l, _class_weights(ytr_l), Xva[keep], np.searchsorted(present, yva[keep]))
        wt.to_cpu(model)
    mdir = run_dir / "models" / name
    mdir.mkdir(parents=True, exist_ok=True)
    model_path = wt.save_model(model, mdir)
    wt.write_json(mdir / "model_info.json", {
        "name": name, "algo": wt.ALGO, "spec": spec, "model_file": model_path.name,
        "base_features": data["feats"], "classes": [C.CLASSES[i] for i in present],
    })
    info = {"n_features": int(Xtr.shape[1]), "train_time_s": perf["train_time_s"], "train_device": device,
            "train_peak_ram_mb": mem.peak_mb, "best_iteration": wt.best_iteration(model),
            "model_size_mb": model_path.stat().st_size / 2**20, "model_dir": str(mdir)}
    return model, present, info


# ---------------------------------------------------------------- live (IoT) measurement
def measure_live(model_dirs: list[Path], threshold: float | None, sample_path: Path, out_path: Path) -> None:
    """Own process, 1 CPU thread. One model, or BAL + FLAT safety net when 2 dirs are given."""
    import pandas as pd
    import psutil
    from common.bench import PeakMemory
    import train_solo  # noqa: F401  (loaded before the RAM baseline, used by build_X)

    proc = psutil.Process()

    def rss() -> float:
        return proc.memory_info().rss / 2**20

    from common import config as C
    infos = [json.loads((d / "model_info.json").read_text(encoding="utf-8")) for d in model_dirs]
    for i in infos:
        wt.import_algo_lib(i["algo"])
    feats = infos[0]["base_features"]
    S = max([w for i in infos for w in i["spec"]["windows"]] + [1]) - 1
    rss_imports = rss()
    df = pd.DataFrame(np.load(sample_path), columns=feats)
    rss_data = rss()
    models = [(wt.load_live(d, i), i["spec"], np.array([C.CLASS_TO_ID[c] for c in i["classes"]]))
              for d, i in zip(model_dirs, infos)]

    def run(chunk) -> np.ndarray:
        ps = [(predict(build_X(chunk, feats, spec, S)), ids) for predict, spec, ids in models]
        if len(ps) == 1:
            return ps[0][1][ps[0][0].argmax(1)]
        return combine(ps[0][0], ps[0][1], ps[1][0], ps[1][1], threshold)

    run(df.iloc[:S + 10])                                   # warm-up
    rss_model = rss()
    n = 0
    with PeakMemory(interval=0.01) as mem:
        t0 = time.perf_counter()
        for i in range(S, len(df), wt.LIVE_CHUNK):
            n += len(run(df.iloc[i - S: i + wt.LIVE_CHUNK]))
        stream_s = time.perf_counter() - t0
    idx = np.linspace(S, len(df) - 1, wt.LATENCY_WARMUP + wt.LATENCY_REPEATS).astype(int)
    lat = []
    for k, j in enumerate(idx):
        t0 = time.perf_counter()
        run(df.iloc[j - S: j + 1])
        if k >= wt.LATENCY_WARMUP:
            lat.append((time.perf_counter() - t0) * 1000)
    wt.write_json(out_path, {
        "threads": 1, "flows_streamed": n, "flows_per_s": n / stream_s,
        "latency_ms_median": float(np.median(lat)), "latency_ms_p95": float(np.percentile(lat, 95)),
        "process_ram_after_imports_mb": rss_imports, "model_ram_mb": rss_model - rss_data,
        "live_peak_ram_mb": mem.peak_mb,
    })


def run_live(model_dirs: list[Path], threshold: float | None, sample: Path, out: Path, log) -> dict | None:
    env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
               CUDA_VISIBLE_DEVICES="")
    cmd = [sys.executable, str(Path(__file__).resolve()), "--measure-live", str(sample), str(out),
           "none" if threshold is None else str(threshold)] + [str(d) for d in model_dirs]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=3600)
    if r.returncode != 0 or not out.exists():
        log.error("live test failed for %s:\n%s%s", out.parent.name, r.stdout, r.stderr)
        return None
    return json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- report
ROWS = [
    ("Attack/benign F1", "binary.f1", "f4"),
    ("False alarm rate", "binary.false_positive_rate", "pct"),
    ("Macro F1", "macro_f1", "f4"),
    ("Hidden single attacks detected", "hidden_detection", "pct"),
    ("Solo attacks detected", "solo_unit_detection", "pct"),
    ("Attack start detected", "start_detection", "pct"),
    ("Single-flow attacks: right class", "point_right_class", "pct"),
    ("Time-series attacks: right class", "series_right_class", "pct"),
    ("Spill-over false alarms", "spillover_false_alarm", "pct"),
    ("**Balance score**", "balance_score", "pct"),
]


def table(results: dict, split: str) -> list[str]:
    names = list(results)
    L = ["| Metric | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for label, path, kind in ROWS:
        L.append(f"| {label} | " + " | ".join(wt.fmt(wt.g(results[n], f"{split}.{path}"), kind) for n in names) + " |")
    return L


def report(results: dict, chosen: str, ens_info: dict, start: int, dropped: list[str]) -> str:
    L = [f"# Balanced {wt.N('flat')} detector: single attacks AND time-series attacks (TRUST Lab)", "",
         f"Features dropped: **{', '.join(dropped) or 'none'}**.", "",
         f"Chosen on validation: **{chosen}** (highest balance score; false alarms within "
         f"{100 * FPR_BUDGET:.1f} pp of the best BAL model).", "",
         "Balance score = harmonic mean of: hidden single-attack detection, single-flow attacks right class, "
         "time-series attacks right class. It is only high when ALL three are high.", "",
         f"Ensemble: {ens_info['base']} decides; FLAT adds an alert only when its attack probability ≥ "
         f"**{ens_info['threshold']}** (tuned on validation).", "",
         "## 1. Validation (solo + burst stream) — used for the choice", ""]
    L += table(results, "val")
    L += ["", "## 2. TEST_ORIGINAL (the normal test stream, fair for every model)", ""]
    L += table(results, "test_original")
    L += ["", "## 3. TEST_SOLO (same test flows, many solo attacks)", ""]
    L += table(results, "test_solo")
    L += ["", "## 4. IoT cost (live, 1 CPU thread)", "",
          "| Model | Features | Model size (MB) | Model RAM (MB) | Live process RAM (MB) | Packets/s | Latency median (ms) |",
          "|---|---|---|---|---|---|---|"]
    for n, r in results.items():
        L.append(f"| {n} | {r.get('n_features', '–')} | {wt.fmt(r.get('model_size_mb'), 'f1')} "
                 f"| {wt.fmt(wt.g(r, 'live.model_ram_mb'), 'f1')} | {wt.fmt(wt.g(r, 'live.live_peak_ram_mb'), 'f0')} "
                 f"| {wt.fmt(r.get('equiv_packets_per_s'), 'f0')} | {wt.fmt(wt.g(r, 'live.latency_ms_median'), 'f3')} |")
    L += ["", "## 5. Charts", ""] + [f"![{c}](charts/{c})" for c in CHART_FILES]
    L += ["", "## Notes", "",
          f"- Single-flow attacks: {', '.join(wt.POINT_ATTACKS)}. Time-series attacks: {', '.join(wt.SERIES_ATTACKS)}.",
          f"- Hidden = attack flow with < {int(wt.HIDDEN_SHARE * 100)}% attacks among the last {wt.REF_WINDOW} flows. "
          "Solo = attack unit of 1-5 flows put alone among normal flows (only in the solo streams).",
          f"- All models are scored from row {start} of each stream, so every model sees the same flows.",
          "- Labels are used only to arrange the streams; no model ever sees a label as input.",
          f"- All models here are {wt.N('flat')}. Live RAM includes Python, pandas and the model library. "
          "The ensemble runs 2 models."]
    return "\n".join(L) + "\n"


def make_charts(results: dict, chosen: str, out_dir: Path, log) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import PercentFormatter
    except ImportError:
        log.warning("matplotlib not installed: charts skipped")
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "figure.facecolor": wt.SURFACE, "axes.facecolor": wt.SURFACE, "savefig.facecolor": wt.SURFACE,
        "axes.edgecolor": wt.GRID, "axes.grid": True, "axes.grid.axis": "x", "grid.color": wt.GRID,
        "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True,
        "text.color": wt.INK, "axes.labelcolor": wt.INK2, "xtick.color": wt.INK2, "ytick.color": wt.INK2,
        "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold",
    })
    names = list(results)
    colors = [wt.SLOT[1] if n == chosen else wt.SLOT[0] for n in names]

    def bars(ax, title, vals, kind, lower_better=False):
        v = [np.nan if x is None else x for x in vals]
        ax.barh(range(len(names)), v, color=colors, height=0.6)
        ax.set_yticks(range(len(names)), names)
        ax.invert_yaxis()
        ax.set_title(title + ("  (lower is better)" if lower_better else ""), loc="left")
        finite = [x for x in v if np.isfinite(x)]
        if kind == "pct":
            ax.xaxis.set_major_formatter(PercentFormatter(1.0, decimals=1))
            if finite and not lower_better:
                lo = min(finite)
                ax.set_xlim(max(0.0, lo - (1 - lo) * 0.6 - 0.005), 1.0)
        for i, x in enumerate(v):
            if np.isfinite(x):
                ax.text(x, i, " " + wt.fmt(x, kind), va="center", fontsize=8, color=wt.INK)

    panels = [("Hidden single attacks detected", "hidden_detection", False),
              ("Attack start detected", "start_detection", False),
              ("Single-flow attacks: right class", "point_right_class", False),
              ("Time-series attacks: right class", "series_right_class", False),
              ("False alarm rate", "binary.false_positive_rate", True),
              ("Balance score", "balance_score", False)]
    for fname, split, title in [(CHART_FILES[0], "test_original", "TEST_ORIGINAL"),
                                (CHART_FILES[1], "test_solo", "TEST_SOLO (many solo attacks)")]:
        fig, axs = plt.subplots(3, 2, figsize=(12, 9))
        fig.suptitle(f"{wt.N('flat')}: single vs time-series attacks — {title}. Orange = chosen ({chosen})",
                     fontweight="bold", x=0.01, ha="left")
        for ax, (t, path, lb) in zip(axs.ravel(), panels):
            bars(ax, t, [wt.g(results[n], f"{split}.{path}") for n in names], "pct", lb)
        fig.tight_layout(rect=(0, 0, 0.97, 0.95))
        fig.savefig(out_dir / fname, dpi=150, bbox_inches="tight")
        plt.close(fig)
        log.info("chart saved: %s", out_dir / fname)

    fig, axs = plt.subplots(1, 3, figsize=(14, 3.8))
    fig.suptitle(f"{wt.N('flat')} IoT cost, 1 CPU thread. Orange = chosen model ({chosen})", fontweight="bold", x=0.01, ha="left")
    bars(axs[0], "Live process RAM (MB)", [wt.g(results[n], "live.live_peak_ram_mb") for n in names], "f0", True)
    bars(axs[1], "Packets per second", [results[n].get("equiv_packets_per_s") for n in names], "f0")
    bars(axs[2], "Latency per flow (ms)", [wt.g(results[n], "live.latency_ms_median") for n in names], "f2", True)
    fig.tight_layout(rect=(0, 0, 0.97, 0.9))
    fig.savefig(out_dir / CHART_FILES[2], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[2])


# ---------------------------------------------------------------- main
def parse_args():
    ap = argparse.ArgumentParser(description="balanced single + time-series attack detector")
    ap.add_argument("--algo", choices=list(wt.NAMES), default="xgboost", help="xgboost (default) or lightgbm")
    ap.add_argument("--quick", action="store_true", help="code check: 20 trees")
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=-1)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    ap.add_argument("--fpr-budget", type=float, default=FPR_BUDGET)
    ap.add_argument("--drop-bulk", action="store_true", help="train without the 6 bulk features (version leak)")
    ap.add_argument("--measure-live", nargs="+", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.gpu_id, args.gpu_platform = 0, 0
    wt.set_algo(args.algo, args)
    return args


def main() -> int:
    args = parse_args()
    if args.measure_live:
        sample, out, thr, *dirs = args.measure_live
        measure_live([Path(d) for d in dirs], None if thr == "none" else float(thr), Path(sample), Path(out))
        return 0

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{wt.N('run')}_balanced{'_nobulk' if args.drop_bulk else ''}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    log = wt.setup_logging(run_dir)
    t_start = time.time()
    results: dict = {}
    out: dict = {"status": "error", "algo": wt.ALGO, "run_dir": str(run_dir)}
    try:
        np.random.seed(42)
        if args.quick:
            args.trees = 20
        from common import config as C
        from common.data import load_meta, load_split
        from common.gbm import _pick_device
        from train_solo import build_mixed_stream, class_parts

        meta = load_meta()
        env = wt.log_environment(log)
        device = _pick_device(wt.ALGO, args)
        start = first_row(SPECS)
        config = {"script": SCRIPT_NAME, "algo": wt.ALGO, "drop_bulk": args.drop_bulk,
                  "dropped_features": wt.BULK_FEATURES if args.drop_bulk else [], "quick": args.quick, "trees": args.trees, "lr": args.lr,
                  "train_device": device, "seed": C.SEED, "specs": SPECS, "scored_from_row": start,
                  "solo_share": SOLO_SHARE, "other_share": OTHER_SHARE, "solo_gap": SOLO_GAP,
                  "test_solo_share": TEST_SOLO_SHARE, "fpr_budget": args.fpr_budget, "thresholds": THRESHOLDS,
                  "point_attacks": wt.POINT_ATTACKS, "series_attacks": wt.SERIES_ATTACKS,
                  "processed_data_quick_mode": meta["quick"], "environment": env}
        wt.write_json(run_dir / "config.json", config)
        log.info("settings: algo %s, trees %d, device %s, scored from row %d, models %s",
                 wt.ALGO, args.trees, device, start, list(SPECS) + ["ENS"])
        if meta["quick"]:
            log.warning("processed data is from preprocess --quick mode: numbers are NOT real results")
        feats = wt.model_features(meta, args.drop_bulk)
        log.info("model features: %d%s", len(feats), " (6 bulk features dropped)" if args.drop_bulk else "")

        # ---- streams: original (train/val/test) + solo (train/val/test)
        log.info("building streams (labels only used to arrange flows) ...")
        streams = {"original": {s: load_split(s) for s in ("train", "val", "test")}, "solo": {}}
        for i, s in enumerate(("train", "val")):
            streams["solo"][s] = build_mixed_stream(class_parts(s), np.random.default_rng(C.SEED + 100 + i),
                                                    SOLO_SHARE, OTHER_SHARE, SOLO_GAP)
        streams["solo"]["test"] = build_mixed_stream(class_parts("test"), np.random.default_rng(C.SEED + 200),
                                                     TEST_SOLO_SHARE, TEST_SOLO_SHARE, SOLO_GAP)
        for kind, d in streams.items():
            for s, df in d.items():
                log.info("  %s/%s: %s flows", kind, s, f"{len(df):,}")

        # ---- train each model on its own stream; validation for the choice = SOLO val stream
        models = {}
        for name, spec in SPECS.items():
            st = streams[spec["stream"]]
            data = {"feats": feats}
            for s in ("train", "val"):
                y, _, _ = targets(st[s], start)
                data[s] = {"X": {name: build_X(st[s], feats, spec, start)}, "y": y}
            model, present, info = train(name, spec, data, args, device, run_dir, log)
            models[name] = (model, present)
            results[name] = dict(info)
            del data

        # ---- predict probabilities on the 3 evaluation streams
        evals = {"val": streams["solo"]["val"], "test_original": streams["original"]["test"],
                 "test_solo": streams["solo"]["test"]}
        probs, truth = {}, {}
        for split, df in evals.items():
            truth[split] = (*targets(df, start)[:2], masks_for(df, start))
            probs[split] = {n: m.predict_proba(build_X(df, feats, SPECS[n], start)) for n, (m, _) in models.items()}
            for n, (_, present) in models.items():
                y, burst, masks = truth[split]
                results[n][split] = score(y, present[probs[split][n].argmax(1)], burst, masks)
            log.info("scored %s", split)

        # ---- ensemble: best BAL + FLAT safety net, threshold tuned on validation
        bal = max(["BAL_W16", "BAL_MS"], key=lambda n: results[n]["val"]["balance_score"])
        bal_fpr = results[bal]["val"]["binary"]["false_positive_rate"]
        y, burst, masks = truth["val"]
        sweep = []
        for t in THRESHOLDS:
            pred = combine(probs["val"][bal], models[bal][1], probs["val"]["FLAT"], models["FLAT"][1], t)
            s = score(y, pred, burst, masks)
            sweep.append({"threshold": t, "balance_score": s["balance_score"],
                          "false_positive_rate": s["binary"]["false_positive_rate"],
                          "hidden_detection": s["hidden_detection"]})
            log.info("  ENS threshold %.3f: balance %s | false alarms %s | hidden %s", t,
                     wt.fmt(s["balance_score"], "pct"), wt.fmt(s["binary"]["false_positive_rate"], "pct"),
                     wt.fmt(s["hidden_detection"], "pct"))
        ok = [r for r in sweep if r["false_positive_rate"] <= bal_fpr + args.fpr_budget] or [sweep[-1]]
        thr = max(ok, key=lambda r: r["balance_score"])["threshold"]
        ens = {"base": bal, "threshold": thr, "sweep": sweep}
        results["ENS"] = {"members": [bal, "FLAT"], "threshold": thr,
                          "model_size_mb": results[bal]["model_size_mb"] + results["FLAT"]["model_size_mb"],
                          "n_features": f"{results[bal]['n_features']} + {results['FLAT']['n_features']}"}
        for split in evals:
            y, burst, masks = truth[split]
            pred = combine(probs[split][bal], models[bal][1], probs[split]["FLAT"], models["FLAT"][1], thr)
            results["ENS"][split] = score(y, pred, burst, masks)
        ens_dir = run_dir / "models" / "ENS"
        ens_dir.mkdir(parents=True, exist_ok=True)
        wt.write_json(ens_dir / "ensemble.json", {"members": [bal, "FLAT"], "threshold": thr,
                                                  "rule": "BAL decides; FLAT adds an alert if P(attack) >= threshold"})
        del probs

        # ---- live IoT cost (separate process, 1 thread)
        sample = run_dir / "live_sample.npy"
        np.save(sample, streams["original"]["test"][feats].to_numpy(np.float32)[:wt.LIVE_SAMPLE_FLOWS])
        del streams
        mdir = run_dir / "models"
        for n in list(SPECS) + ["ENS"]:
            dirs = [mdir / bal, mdir / "FLAT"] if n == "ENS" else [mdir / n]
            log.info("[%s] live test (1 thread) ...", n)
            results[n]["live"] = run_live(dirs, thr if n == "ENS" else None, sample, mdir / n / "live.json", log)
            f = wt.g(results[n], "live.flows_per_s")
            results[n]["equiv_packets_per_s"] = None if f is None else f * meta["avg_packets_per_flow_test"]
        sample.unlink(missing_ok=True)

        # ---- choice on validation: best balance score, false alarms within budget of the best BAL
        cand = [n for n in results
                if results[n]["val"]["binary"]["false_positive_rate"] <= bal_fpr + args.fpr_budget]
        chosen = max(cand, key=lambda n: results[n]["val"]["balance_score"])
        for n, r in results.items():
            log.info("%-8s val balance %s | TEST_ORIGINAL: hidden %s, single right %s, series right %s, "
                     "false alarms %s | TEST_SOLO: solo %s | packets/s %s", n,
                     wt.fmt(r["val"]["balance_score"], "pct"), wt.fmt(r["test_original"]["hidden_detection"], "pct"),
                     wt.fmt(r["test_original"]["point_right_class"], "pct"),
                     wt.fmt(r["test_original"]["series_right_class"], "pct"),
                     wt.fmt(r["test_original"]["binary"]["false_positive_rate"], "pct"),
                     wt.fmt(r["test_solo"]["solo_unit_detection"], "pct"), wt.fmt(r.get("equiv_packets_per_s"), "f0"))
        (run_dir / "BALANCED.md").write_text(report(results, chosen, ens, start,
                                                         wt.BULK_FEATURES if args.drop_bulk else []),
                                                  encoding="utf-8")
        make_charts(results, chosen, run_dir / "charts", log)
        out.update({"status": "ok", "chosen": chosen, "ensemble": ens})
        log.info("chosen (validation): %s", chosen)
        log.info("report: %s", run_dir / "BALANCED.md")
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    out["models"] = results
    wt.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.0f s)", out["time_taken_s"])
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
