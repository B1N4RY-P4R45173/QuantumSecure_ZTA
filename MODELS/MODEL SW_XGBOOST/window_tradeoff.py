"""
SW-XGBoost window trade-off for IoT: windows 8, 16, 24, ..., 64 vs plain XGBoost (1 flow).
Same study for LightGBM with --algo lightgbm (output folder runs/sw_lgbm_window_tradeoff_<ts>/).

    python "MODELS/MODEL SW_XGBOOST/window_tradeoff.py"                      # full run
    python "MODELS/MODEL SW_XGBOOST/window_tradeoff.py" --algo lightgbm      # same, LightGBM
    python "MODELS/MODEL SW_XGBOOST/window_tradeoff.py" --quick              # 2 windows, few trees: code check
    python "MODELS/MODEL SW_XGBOOST/window_tradeoff.py" --windows 8 32 64
    python "MODELS/MODEL SW_XGBOOST/window_tradeoff.py" --plot-only runs/<run folder>   # redraw charts

For every window (and for plain XGBoost) it trains one model exactly like
MODEL SW_XGBOOST/train.py and measures:

  Detection    attack/benign F1, detection rate, false alarm rate, macro F1 (16 classes)
  Attack type  POINT attacks (can be a single flow) vs TIME-SERIES attacks (many flows),
               hidden attacks (an attack among mostly normal flows), attack start,
               spill-over false alarms (normal flows inside an attack burst), time to detect
  Live cost    measured in a SEPARATE process with 1 CPU thread, like an IoT gateway:
               process RAM, model RAM, model size, packets/s, latency per flow

Fair test: every model is scored on the same rows, the window is CHOSEN on validation
(never on test). Nothing outside runs/ is written; existing models are not touched.

Saves: runs/sw_xgb_window_tradeoff_<YYYYMMDD_HHMMSS>/
       run.log, config.json, results.json, WINDOW_TRADEOFF.md, charts/*.png, models/<name>/
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
MODELS_DIR = HERE.parent
PROJECT_ROOT = MODELS_DIR.parent
sys.path.insert(0, str(MODELS_DIR))

# ---------------------------------------------------------------- settings
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "sw_xgb_window_tradeoff"

# The 6 bulk features leak the CICFlowMeter version in TRUST Lab: always 0 in Benign, DDoS, DoS,
# PortScan, Slowloris (old version), non-zero in the other 10 attack classes (new version).
# --drop-bulk trains without them (see MODELS/results/BEST_MODEL.md section 7).
BULK_FEATURES = ["Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
                 "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"]


def model_features(meta: dict, drop_bulk: bool) -> list[str]:
    feats = list(meta["features"])
    return [f for f in feats if f not in BULK_FEATURES] if drop_bulk else feats


# ---------------------------------------------------------------- algorithm (--algo)
ALGO = "xgboost"
NAMES = {
    "xgboost": {"flat": "XGBoost", "sw": "SW-XGBoost", "short": "XGB", "run": "sw_xgb",
                "flat_name": "XGBOOST_1flow", "sw_prefix": "SW_XGB"},
    "lightgbm": {"flat": "LightGBM", "sw": "SW-LightGBM", "short": "LGBM", "run": "sw_lgbm",
                 "flat_name": "LIGHTGBM_1flow", "sw_prefix": "SW_LGBM"},
}


def set_algo(algo: str, args=None) -> None:
    global ALGO
    ALGO = algo
    # LightGBM's GPU (OpenCL) learner uses single precision and crashes on this data with
    # "Check failed: best_split_info.left_count > 0". Train LightGBM on CPU unless asked.
    if algo == "lightgbm" and args is not None and getattr(args, "device", None) == "auto":
        args.device = "cpu"


def N(key: str) -> str:
    """Display name for the current algorithm, e.g. N('sw') -> 'SW-LightGBM'."""
    return NAMES[ALGO][key]


def fit_model(model, Xtr, ytr_l, weights, Xva, yva_l) -> None:
    """Train with early stopping on validation (30 rounds), like common/gbm.py."""
    if ALGO == "xgboost":
        model.fit(Xtr, ytr_l, sample_weight=weights, eval_set=[(Xva, yva_l)], verbose=False)
    else:
        import lightgbm as lgb
        model.fit(Xtr, ytr_l, sample_weight=weights, eval_set=[(Xva, yva_l)],
                  callbacks=[lgb.early_stopping(30, verbose=False)])


def to_cpu(model) -> None:
    if ALGO == "xgboost":
        model.set_params(device="cpu")                    # edge gateways have no GPU


def save_model(model, model_dir: Path) -> Path:
    if ALGO == "xgboost":
        path = model_dir / "model.json"
        model.save_model(path)
    else:
        path = model_dir / "model.txt"
        model.booster_.save_model(str(path))
    return path


def best_iteration(model):
    return getattr(model, "best_iteration", None) if ALGO == "xgboost" else getattr(model, "best_iteration_", None)


def import_algo_lib(algo: str) -> None:
    """Import the library before a RAM baseline is taken."""
    if algo == "xgboost":
        import xgboost  # noqa: F401
    else:
        import lightgbm  # noqa: F401


def load_live(model_dir: Path, info: dict):
    """Saved model -> predict_proba function that uses ONE CPU thread."""
    if info["algo"] == "xgboost":
        from xgboost import XGBClassifier
        m = XGBClassifier()
        m.load_model(model_dir / info["model_file"])
        m.set_params(n_jobs=1, device="cpu")
        return m.predict_proba
    import lightgbm as lgb
    b = lgb.Booster(model_file=str(model_dir / info["model_file"]))
    return lambda X: b.predict(X, num_threads=1)
DEFAULT_WINDOWS = [8, 16, 24, 32, 40, 48, 56, 64]
QUICK_WINDOWS = [8, 16]

# Attack types. POINT = one flow can be the whole attack (same list as train_solo.py SOLO_TYPE).
# TIME-SERIES = the attack is many flows (floods, scans, guessing).
POINT_ATTACKS = ["Exploitation", "BufferOverflow", "WebBased", "API", "TLSSSL", "C2Beaconing", "Exfiltration"]
SERIES_ATTACKS = ["DDoS", "DoS", "Slowloris", "PortScan", "Bruteforce", "DNS", "MITM", "Evasion"]

# Context of a flow, judged on a FIXED window so every model is judged on the same flows.
REF_WINDOW = 32          # look at the last 32 flows
HIDDEN_SHARE = 0.25      # attack flow with < 25% attack flows around it = hidden attack
BUSY_SHARE = 0.75        # normal flow with >= 75% attack flows around it = spill-over risk
START_FLOWS = 5          # first 5 attack flows of a burst = attack start

KNEE_TOL = 0.005         # chosen window = smallest window within 0.005 val macro F1 of the best
LIVE_SAMPLE_FLOWS = 20_000
LIVE_CHUNK = 256         # flows per micro-batch in the live test
LATENCY_WARMUP = 50
LATENCY_REPEATS = 300

# Chart colors (dataviz reference palette, light mode; categorical slots in fixed order)
SURFACE, INK, INK2, GRID = "#fcfcfb", "#1f1f1e", "#5f5e5a", "#e4e3df"
SLOT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
BLUE_RAMP = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]


# ---------------------------------------------------------------- logging
class _Tee:
    """Copy everything written to stdout/stderr (also from libraries) into run.log."""

    def __init__(self, stream, path: Path):
        self.stream, self.file = stream, open(path, "a", encoding="utf-8", buffering=1)

    def write(self, s):
        self.stream.write(s)
        self.file.write(s)

    def flush(self):
        self.stream.flush()
        self.file.flush()


def setup_logging(run_dir: Path) -> logging.Logger:
    log_path = run_dir / "run.log"
    sys.stdout = _Tee(sys.__stdout__, log_path)
    sys.stderr = _Tee(sys.__stderr__, log_path)
    log = logging.getLogger(SCRIPT_NAME)
    log.setLevel(logging.INFO)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(h)
    return log


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, default=float), encoding="utf-8")


def log_environment(log: logging.Logger) -> dict:
    env = {"python": sys.version.replace("\n", " "), "executable": sys.executable,
           "platform": platform.platform()}
    env["algo"] = ALGO
    for lib in ("xgboost", "lightgbm"):
        try:
            env[lib] = __import__(lib).__version__
        except ImportError:
            env[lib] = None
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=20)
        env["gpus"] = [g.strip() for g in out.stdout.splitlines() if g.strip()]
    except Exception as e:                       # no nvidia-smi
        env["gpus"] = [f"not found ({e.__class__.__name__})"]
    for k, v in env.items():
        log.info("%s: %s", k, v)
    return env


# ---------------------------------------------------------------- inputs
def build_inputs(df, feats: list[str], window: int, start: int):
    """Model inputs from row `start` on. window 1 = plain XGBoost (one flow)."""
    from common.windows import sliding_window_features, targets
    if window == 1:
        return (df[feats].to_numpy(np.float32)[start:], df["label"].to_numpy(np.int64)[start:],
                df["burst"].to_numpy(np.int64)[start:])
    X, _ = sliding_window_features(df, feats, window)
    y, burst = targets(df, window)
    cut = start - (window - 1)
    return X[cut:], y[cut:], burst[cut:]


def context_masks(df, start: int) -> dict:
    """Hidden attacks, attack starts and busy normal flows, from row `start` on."""
    import pandas as pd
    from common import config as C
    B = C.CLASS_TO_ID[C.BENIGN]
    lab = df["label"].to_numpy(np.int64)
    att = lab != B
    share = pd.Series(att.astype(np.float32)).rolling(REF_WINDOW).mean().to_numpy()
    burst = df["burst"].to_numpy(np.int64)
    pos = np.full(len(lab), -1)
    m = burst >= 0
    s = pd.Series(burst[m])
    pos[m] = s.groupby(s).cumcount().to_numpy()
    sl = slice(start, None)
    return {
        "hidden": (att & (share < HIDDEN_SHARE))[sl],
        "start": (att & m & (pos < START_FLOWS))[sl],
        "busy": (~att & (share >= BUSY_SHARE))[sl],
    }


def score(y: np.ndarray, pred: np.ndarray, burst: np.ndarray, masks: dict) -> dict:
    from common import config as C
    from common.metrics import evaluate
    B = C.CLASS_TO_ID[C.BENIGN]
    out = evaluate(y, pred, burst)
    hit = pred != B

    def share(mask, values):
        return float(values[mask].mean()) if mask.any() else None

    for gname, classes in (("point", POINT_ATTACKS), ("series", SERIES_ATTACKS)):
        g = np.isin(y, [C.CLASS_TO_ID[c] for c in classes])
        out[f"{gname}_detection"] = share(g, hit)
        out[f"{gname}_right_class"] = share(g, pred == y)
        out[f"{gname}_flows"] = int(g.sum())
    out["hidden_detection"] = share(masks["hidden"], hit)
    out["start_detection"] = share(masks["start"], hit)
    out["spillover_false_alarm"] = share(masks["busy"], hit)
    out["context_counts"] = {k: int(v.sum()) for k, v in masks.items()}
    return out


# ---------------------------------------------------------------- training
def train_one(name: str, window: int, splits: dict, masks: dict, feats: list[str], start: int,
              args, device: str, run_dir: Path, log: logging.Logger) -> dict:
    from common import config as C
    from common.bench import PeakMemory, timed
    from common.gbm import _class_weights, _make_model
    perf: dict = {}
    with PeakMemory() as mem:
        data = {}
        for split, df in splits.items():
            with timed(perf, f"features_{split}_s"):
                data[split] = build_inputs(df, feats, window, start)
        Xtr, ytr, _ = data["train"]
        Xva, yva, bva = data["val"]
        Xte, yte, bte = data["test"]

        present = np.unique(ytr)
        ytr_l = np.searchsorted(present, ytr)
        keep_va = np.isin(yva, present)
        model = _make_model(ALGO, len(present), args, device)
        log.info("[%s] training on %s rows, %d features (%s) ...", name, f"{len(Xtr):,}", Xtr.shape[1], device)
        with timed(perf, "train_time_s"):
            fit_model(model, Xtr, ytr_l, _class_weights(ytr_l),
                      Xva[keep_va], np.searchsorted(present, yva[keep_va]))
        to_cpu(model)
        pred_va = present[model.predict(Xva).astype(int).ravel()]
        with timed(perf, "predict_test_s"):
            pred_te = present[model.predict(Xte).astype(int).ravel()]

    model_dir = run_dir / "models" / name
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = save_model(model, model_dir)
    write_json(model_dir / "model_info.json", {
        "name": name, "algo": ALGO, "windowed": window > 1, "window": window,
        "model_file": model_path.name, "base_features": feats,
        "classes": [C.CLASSES[i] for i in present],
    })
    res = {
        "name": name, "kind": "sw" if window > 1 else "flat", "window": window,
        "n_features": int(Xtr.shape[1]),
        "train_time_s": perf["train_time_s"], "train_device": device,
        "best_iteration": best_iteration(model),
        "train_peak_ram_mb": mem.peak_mb,
        "model_size_mb": model_path.stat().st_size / 2**20,
        "batch_flows_per_s_all_threads": len(Xte) / (perf["features_test_s"] + perf["predict_test_s"]),
        "val": score(yva, pred_va, bva, masks["val"]),
        "test": score(yte, pred_te, bte, masks["test"]),
        "model_dir": str(model_dir),
    }
    write_json(model_dir / "result.json", res)
    return res


# ---------------------------------------------------------------- live (IoT) measurement
def measure_live(model_dir: Path, sample_path: Path, out_path: Path) -> None:
    """Runs in its own process, 1 CPU thread. Streams flows through the saved model."""
    import pandas as pd
    import psutil
    from common.bench import PeakMemory
    from common.windows import flow_only_features, sliding_window_features

    proc = psutil.Process()

    def rss() -> float:
        return proc.memory_info().rss / 2**20

    info = json.loads((model_dir / "model_info.json").read_text(encoding="utf-8"))
    import_algo_lib(info["algo"])
    feats, w = info["base_features"], int(info["window"])
    build = sliding_window_features if info["windowed"] else flow_only_features
    rss_imports = rss()
    df = pd.DataFrame(np.load(sample_path), columns=feats)
    rss_data = rss()
    predict = load_live(model_dir, info)
    predict(build(df.iloc[:w + 10], feats, w)[0]).argmax(1)  # warm-up
    rss_model = rss()

    n = 0
    with PeakMemory(interval=0.01) as mem:
        t0 = time.perf_counter()
        for i in range(w - 1, len(df), LIVE_CHUNK):
            X, _ = build(df.iloc[i - (w - 1): i + LIVE_CHUNK], feats, w)
            predict(X).argmax(1)
            n += len(X)
        stream_s = time.perf_counter() - t0

    idx = np.linspace(w - 1, len(df) - 1, LATENCY_WARMUP + LATENCY_REPEATS).astype(int)
    lat = []
    for k, j in enumerate(idx):
        t0 = time.perf_counter()
        X, _ = build(df.iloc[j - (w - 1): j + 1], feats, w)   # the last w flows -> 1 input
        predict(X).argmax(1)
        if k >= LATENCY_WARMUP:
            lat.append((time.perf_counter() - t0) * 1000)

    write_json(out_path, {
        "threads": 1,
        "flows_streamed": n,
        "flows_per_s": n / stream_s,
        "latency_ms_median": float(np.median(lat)),
        "latency_ms_p95": float(np.percentile(lat, 95)),
        "process_ram_after_imports_mb": rss_imports,
        "model_ram_mb": rss_model - rss_data,
        "live_peak_ram_mb": mem.peak_mb,
        "live_extra_ram_mb": mem.peak_mb - rss_imports,
    })


def run_live(model_dir: Path, sample: Path, log: logging.Logger) -> dict | None:
    out = model_dir / "live.json"
    env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
               CUDA_VISIBLE_DEVICES="")
    r = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--measure-live",
                        str(model_dir), str(sample), str(out)],
                       env=env, capture_output=True, text=True, timeout=3600)
    if r.returncode != 0 or not out.exists():
        log.error("live test failed for %s:\n%s%s", model_dir.name, r.stdout, r.stderr)
        return None
    return json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- choice
def g(r: dict, path: str):
    """Get a nested value like 'test.binary.f1'; None if missing."""
    v = r
    for k in path.split("."):
        if not isinstance(v, dict) or v.get(k) is None:
            return None
        v = v[k]
    return v


def equiv_pkts(r: dict, avg_pkts: float):
    f = g(r, "live.flows_per_s")
    return None if f is None else f * avg_pkts


def choose(results: list[dict], args) -> dict:
    sw = [r for r in results if r["kind"] == "sw"]
    best_f1 = max(sw, key=lambda r: (g(r, "val.binary.f1"), -g(r, "val.binary.false_positive_rate")))
    best_macro = max(sw, key=lambda r: g(r, "val.macro_f1"))
    target = g(best_macro, "val.macro_f1") - KNEE_TOL
    knee = min((r for r in sw if g(r, "val.macro_f1") >= target), key=lambda r: r["window"])
    out = {"best_val_f1": best_f1["name"], "best_val_macro_f1": best_macro["name"],
           "chosen_knee": knee["name"], "knee_tolerance": KNEE_TOL, "budget": None}
    if args.ram_budget_mb or args.min_pkts_per_s:
        ok = [r for r in results
              if g(r, "live.live_peak_ram_mb") is not None
              and (not args.ram_budget_mb or g(r, "live.live_peak_ram_mb") <= args.ram_budget_mb)
              and (not args.min_pkts_per_s or (r.get("equiv_packets_per_s") or 0) >= args.min_pkts_per_s)]
        out["budget"] = {"ram_budget_mb": args.ram_budget_mb, "min_pkts_per_s": args.min_pkts_per_s,
                         "best_in_budget": max(ok, key=lambda r: g(r, "val.macro_f1"))["name"] if ok else None}
    return out


# (segment, metric label, path, higher is better, format, tie tolerance)
SEGMENTS = [
    ("Overall", "Attack/benign F1", "test.binary.f1", True, "f4", 0.0005),
    ("Overall", "Detection rate", "test.binary.recall_detection_rate", True, "pct", 0.0005),
    ("Overall", "False alarm rate", "test.binary.false_positive_rate", False, "pct", 0.0002),
    ("Overall", "Macro F1 (right class)", "test.macro_f1", True, "f4", 0.002),
    ("Point attacks", "Detected as attack", "test.point_detection", True, "pct", 0.0005),
    ("Point attacks", "Right class", "test.point_right_class", True, "pct", 0.002),
    ("Time-series attacks", "Detected as attack", "test.series_detection", True, "pct", 0.0005),
    ("Time-series attacks", "Right class", "test.series_right_class", True, "pct", 0.002),
    ("Context", "Hidden attacks detected", "test.hidden_detection", True, "pct", 0.005),
    ("Context", "Attack start detected", "test.start_detection", True, "pct", 0.005),
    ("Context", "Spill-over false alarms", "test.spillover_false_alarm", False, "pct", 0.002),
    ("Context", "Median attack flows before alert", "test.time_to_detect.median_attack_flows_before_alert",
     False, "f1", 0.0),
    ("IoT cost", "Live process RAM (MB)", "live.live_peak_ram_mb", False, "f0", 5.0),
    ("IoT cost", "Model RAM (MB)", "live.model_ram_mb", False, "f1", 1.0),
    ("IoT cost", "Model size on disk (MB)", "model_size_mb", False, "f1", 0.5),
    ("IoT cost", "Packets/s (1 thread)", "equiv_packets_per_s", True, "f0", 0.0),
    ("IoT cost", "Latency per flow (ms)", "live.latency_ms_median", False, "f3", 0.0),
    ("IoT cost", "Training time (s)", "train_time_s", False, "f0", 5.0),
]


def fmt(v, kind: str) -> str:
    if v is None:
        return "–"
    if kind == "pct":
        return f"{100 * v:.2f}%"
    return f"{v:,.{int(kind[1])}f}"


def xgb_vs_sw(results: list[dict], chosen: dict) -> list[dict]:
    base = next((r for r in results if r["kind"] == "flat"), None)
    sw = [r for r in results if r["kind"] == "sw"]
    knee = next(r for r in sw if r["name"] == chosen["chosen_knee"])
    rows = []
    for seg, label, path, hib, kind, tol in SEGMENTS:
        vals = [(g(r, path), r) for r in sw if g(r, path) is not None]
        if not vals or base is None or g(base, path) is None:
            continue
        best_v, best_r = (max if hib else min)(vals, key=lambda t: t[0])
        bv = g(base, path)
        diff = (bv - best_v) if hib else (best_v - bv)        # > 0 means the 1-flow model is better
        winner = "tie" if abs(diff) <= tol else (N("flat") if diff > 0 else f"SW W={best_r['window']}")
        rows.append({"segment": seg, "metric": label, "xgboost": bv, "chosen_sw": g(knee, path),
                     "best_sw": best_v, "best_sw_window": best_r["window"], "winner": winner, "format": kind})
    return rows


def xgb_better_classes(results: list[dict]) -> list[str]:
    base = next((r for r in results if r["kind"] == "flat"), None)
    sw = [r for r in results if r["kind"] == "sw"]
    if base is None:
        return []
    out = []
    for c, pc in base["test"]["per_class"].items():
        if c == "Benign":
            continue
        best_sw = max(g(r, f"test.per_class.{c}.recall") or 0 for r in sw)
        if pc["recall"] > best_sw + 0.002:
            out.append(f"{c} ({100 * pc['recall']:.2f}% vs best SW {100 * best_sw:.2f}%)")
    return out


# ---------------------------------------------------------------- report
def report(results: list[dict], chosen: dict, rows: list[dict], better: list[str], meta: dict) -> str:
    L = [f"# {N('sw')} window trade-off vs plain {N('flat')} (TRUST Lab)", "",
         f"All models scored on the same {results[0]['test']['binary']['tn'] + results[0]['test']['binary']['fp'] + results[0]['test']['binary']['tp'] + results[0]['test']['binary']['fn']:,} test flows. "
         f"Window CHOSEN on validation. Live cost measured with **1 CPU thread** in a separate process.", "",
         f"- Best attack/benign F1 (val): **{chosen['best_val_f1']}**",
         f"- Best macro F1 (val): **{chosen['best_val_macro_f1']}**",
         f"- **Chosen for IoT** (smallest window within {KNEE_TOL} val macro F1 of the best): **{chosen['chosen_knee']}**"]
    if chosen["budget"]:
        b = chosen["budget"]
        L.append(f"- Best inside budget (RAM ≤ {b['ram_budget_mb']} MB, packets/s ≥ {b['min_pkts_per_s']}): "
                 f"**{b['best_in_budget']}**")

    L += ["", "## 1. Detection (test)", "",
          "| Model | F1 | Detection | False alarms | Macro F1 | Val F1 | Val macro F1 |", "|---|---|---|---|---|---|---|"]
    for r in results:
        b = r["test"]["binary"]
        L.append(f"| {r['name']} | {b['f1']:.4f} | {fmt(b['recall_detection_rate'], 'pct')} "
                 f"| {fmt(b['false_positive_rate'], 'pct')} | {r['test']['macro_f1']:.4f} "
                 f"| {r['val']['binary']['f1']:.4f} | {r['val']['macro_f1']:.4f} |")

    L += ["", "## 2. Point vs time-series attacks, and context (test)", "",
          "| Model | Point: detected | Point: right class | Series: detected | Series: right class "
          "| Hidden detected | Start detected | Spill-over false alarms | Median flows before alert |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        t = r["test"]
        L.append(f"| {r['name']} | {fmt(t['point_detection'], 'pct')} | {fmt(t['point_right_class'], 'pct')} "
                 f"| {fmt(t['series_detection'], 'pct')} | {fmt(t['series_right_class'], 'pct')} "
                 f"| {fmt(t['hidden_detection'], 'pct')} | {fmt(t['start_detection'], 'pct')} "
                 f"| {fmt(t['spillover_false_alarm'], 'pct')} "
                 f"| {fmt(g(r, 'test.time_to_detect.median_attack_flows_before_alert'), 'f1')} |")
    cc = results[0]["test"]["context_counts"]
    L += ["", f"Flows in each context group (test): hidden attacks {cc['hidden']:,}, attack starts {cc['start']:,}, "
              f"busy normal flows {cc['busy']:,}."]

    L += ["", "## 3. IoT cost (live, 1 CPU thread)", "",
          "| Model | Features | Model size (MB) | Model RAM (MB) | Live process RAM (MB) | Packets/s | Flows/s "
          "| Latency median / p95 (ms) | Train time (s) | Train peak RAM (MB) |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['name']} | {r['n_features']} | {r['model_size_mb']:.1f} "
                 f"| {fmt(g(r, 'live.model_ram_mb'), 'f1')} | {fmt(g(r, 'live.live_peak_ram_mb'), 'f0')} "
                 f"| {fmt(r.get('equiv_packets_per_s'), 'f0')} | {fmt(g(r, 'live.flows_per_s'), 'f0')} "
                 f"| {fmt(g(r, 'live.latency_ms_median'), 'f3')} / {fmt(g(r, 'live.latency_ms_p95'), 'f3')} "
                 f"| {r['train_time_s']:.0f} ({r['train_device']}) | {r['train_peak_ram_mb']:,.0f} |")

    L += ["", f"## 4. When is plain {N('flat')} best?", "",
          f"`Chosen SW` = {chosen['chosen_knee']}. `Best SW` = best window for that one metric (test).", "",
          f"| Segment | Metric | {N('flat')} (1 flow) | Chosen SW | Best SW (window) | Winner |", "|---|---|---|---|---|---|"]
    for row in rows:
        k = row["format"]
        L.append(f"| {row['segment']} | {row['metric']} | {fmt(row['xgboost'], k)} | {fmt(row['chosen_sw'], k)} "
                 f"| {fmt(row['best_sw'], k)} (W={row['best_sw_window']}) | **{row['winner']}** |")
    L += ["", f"Attack classes where plain {N('flat')} gives the right class more often than EVERY window:", ""]
    L += [f"- {c}" for c in better] or ["- none"]

    L += ["", "## 5. Charts", ""]
    L += [f"![{p}](charts/{p})" for p in CHART_FILES]
    L += ["", "## Notes", "",
          f"- Features dropped: {', '.join(meta.get('dropped_features') or []) or 'none'}.",
          f"- Point attacks: {', '.join(POINT_ATTACKS)}. Time-series attacks: {', '.join(SERIES_ATTACKS)}.",
          f"- Hidden attack = attack flow with < {int(HIDDEN_SHARE * 100)}% attack flows among the last {REF_WINDOW}. "
          f"Spill-over = normal flow with ≥ {int(BUSY_SHARE * 100)}% attack flows among the last {REF_WINDOW}. "
          f"Attack start = first {START_FLOWS} attack flows of a burst. The same flows are used for every model.",
          f"- Packets/s = flows/s × {meta.get('avg_packets_per_flow_test', 0):.2f} average packets per flow. "
          "Flows/s includes building the window features; it does NOT include CICFlowMeter.",
          f"- Live test: {LIVE_SAMPLE_FLOWS:,} test flows streamed in batches of {LIVE_CHUNK}; latency = one flow "
          "(build window features from the last W flows + predict). Live process RAM includes Python, pandas and the model library.",
          "- Train peak RAM covers loading all splits and training on the server; it is NOT the IoT number.",
          "- Winner 'tie' = difference smaller than a small tolerance (for example 0.05 percentage points)."]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- charts
CHART_FILES = ["01_detection_vs_window.png", "02_attack_types_vs_window.png", "03_context_vs_window.png",
               "04_iot_cost_vs_window.png", "05_tradeoff.png", "06_per_class_heatmap.png"]


def make_charts(results: list[dict], chosen: dict, out_dir: Path, log: logging.Logger) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import LinearSegmentedColormap
        from matplotlib.ticker import PercentFormatter
    except ImportError:
        log.warning("matplotlib is not installed: charts skipped. Install it, then run with --plot-only %s",
                    out_dir.parent)
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True,
        "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "axes.titlecolor": INK, "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold",
        "legend.frameon": False,
    })
    base = next((r for r in results if r["kind"] == "flat"), None)
    sw = sorted((r for r in results if r["kind"] == "sw"), key=lambda r: r["window"])
    ws = [r["window"] for r in sw]
    knee_w = next(r["window"] for r in sw if r["name"] == chosen["chosen_knee"])

    def val(r, path):
        v = g(r, path)
        return np.nan if v is None else v

    def panel(ax, title, series, percent=False, lower_better=False):
        """series: list of (label, path). Solid = SW model per window, dashed = plain 1-flow model."""
        for i, (lab, path) in enumerate(series):
            col = SLOT[i]
            ax.plot(ws, [val(r, path) for r in sw], color=col, lw=2, marker="o", ms=7,
                    markeredgecolor=SURFACE, markeredgewidth=1.5, label=f"{N('sw')}{': ' + lab if lab else ''}")
            if base is not None:
                ax.axhline(val(base, path), color=col, lw=1.5, ls="--",
                           label=f"{N('flat')}, 1 flow{': ' + lab if lab else ''}")
        ax.axvline(knee_w, color=INK2, lw=1, ls=":")
        ax.set_title(title + ("  (lower is better)" if lower_better else ""), loc="left")
        ax.set_xticks(ws)
        ax.set_xlabel("Window size (flows)")
        if percent:
            ax.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=1))

    def finish(fig, name, legend_ax):
        h, lab = legend_ax.get_legend_handles_labels()
        h.append(plt.Line2D([], [], color=INK2, lw=1, ls=":"))
        lab.append(f"chosen window (W={knee_w})")
        fig.legend(h, lab, loc="lower center", ncol=min(len(lab), 3), bbox_to_anchor=(0.5, -0.01))
        fig.tight_layout(rect=(0, 0.08, 1, 0.95))
        fig.savefig(out_dir / name, dpi=150, bbox_inches="tight")
        plt.close(fig)
        log.info("chart saved: %s", out_dir / name)

    # 1. detection
    fig, axs = plt.subplots(2, 2, figsize=(11, 7.5))
    fig.suptitle(f"{N('sw')} detection vs window size (test set)", fontweight="bold", x=0.01, ha="left")
    panel(axs[0, 0], "Attack/benign F1", [("", "test.binary.f1")])
    panel(axs[0, 1], "Macro F1 (right attack class)", [("", "test.macro_f1")])
    panel(axs[1, 0], "Detection rate", [("", "test.binary.recall_detection_rate")], percent=True)
    panel(axs[1, 1], "False alarm rate", [("", "test.binary.false_positive_rate")], percent=True, lower_better=True)
    finish(fig, CHART_FILES[0], axs[0, 0])

    # 2. point vs time-series attacks
    fig, axs = plt.subplots(1, 2, figsize=(11, 4.6))
    fig.suptitle("Point attacks vs time-series attacks", fontweight="bold", x=0.01, ha="left")
    both = [("point attacks", "test.point_detection"), ("time-series attacks", "test.series_detection")]
    panel(axs[0], "Detected as an attack", both, percent=True)
    panel(axs[1], "Given the right class",
          [("point attacks", "test.point_right_class"), ("time-series attacks", "test.series_right_class")],
          percent=True)
    finish(fig, CHART_FILES[1], axs[0])

    # 3. context
    fig, axs = plt.subplots(1, 3, figsize=(14, 4.6))
    fig.suptitle(f"Attacks in context (judged on the last {REF_WINDOW} flows)", fontweight="bold", x=0.01, ha="left")
    panel(axs[0], "Hidden attacks detected", [("", "test.hidden_detection")], percent=True)
    panel(axs[1], f"Attack start detected (first {START_FLOWS})", [("", "test.start_detection")], percent=True)
    panel(axs[2], "Spill-over false alarms", [("", "test.spillover_false_alarm")], percent=True, lower_better=True)
    finish(fig, CHART_FILES[2], axs[0])

    # 4. IoT cost
    fig, axs = plt.subplots(2, 2, figsize=(11, 7.5))
    fig.suptitle("IoT cost vs window size (1 CPU thread)", fontweight="bold", x=0.01, ha="left")
    panel(axs[0, 0], "Live process RAM (MB)", [("", "live.live_peak_ram_mb")], lower_better=True)
    panel(axs[0, 1], "Model size on disk (MB)", [("", "model_size_mb")], lower_better=True)
    panel(axs[1, 0], "Packets per second", [("", "equiv_packets_per_s")])
    panel(axs[1, 1], "Latency per flow, median (ms)", [("", "live.latency_ms_median")], lower_better=True)
    finish(fig, CHART_FILES[3], axs[0, 0])

    # 5. trade-off scatter
    fig, axs = plt.subplots(2, 2, figsize=(11, 8))
    fig.suptitle("Trade-off: detection vs speed and RAM (up and right/left is better)", fontweight="bold",
                 x=0.01, ha="left")
    for row, (ypath, ylab) in enumerate([("test.macro_f1", "Macro F1"), ("test.binary.f1", "Attack/benign F1")]):
        for col, (xpath, xlab) in enumerate([("equiv_packets_per_s", "Packets/s, 1 thread (higher is better)"),
                                             ("live.live_peak_ram_mb", "Live process RAM, MB (lower is better)")]):
            ax = axs[row, col]
            xs, ys = [val(r, xpath) for r in sw], [val(r, ypath) for r in sw]
            ax.plot(xs, ys, color=SLOT[0], lw=1, alpha=0.5)
            ax.scatter(xs, ys, color=SLOT[0], s=60, edgecolor=SURFACE, linewidth=1.5, zorder=3, label=N("sw"))
            for r, x, y in zip(sw, xs, ys):
                ax.annotate(f"W{r['window']}", (x, y), textcoords="offset points", xytext=(6, 4), fontsize=8, color=INK2)
            if base is not None:
                bx, by = val(base, xpath), val(base, ypath)
                ax.scatter([bx], [by], color=SLOT[1], marker="s", s=70, edgecolor=SURFACE, linewidth=1.5,
                           zorder=3, label=f"{N('flat')}, 1 flow")
                ax.annotate(N("flat"), (bx, by), textcoords="offset points", xytext=(6, 4), fontsize=8, color=INK2)
            ax.set_xlabel(xlab)
            ax.set_ylabel(ylab)
    h, lab = axs[0, 0].get_legend_handles_labels()
    fig.legend(h, lab, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.05, 1, 0.95))
    fig.savefig(out_dir / CHART_FILES[4], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[4])

    # 6. per-class heatmaps
    cols = ([base] if base is not None else []) + sw
    names = ([N("short")] if base is not None else []) + [f"W{w}" for w in ws]
    classes = [c for c in POINT_ATTACKS + SERIES_ATTACKS if c in cols[0]["test"]["per_class"]]
    cmap = LinearSegmentedColormap.from_list("blue", BLUE_RAMP)
    fig, axs = plt.subplots(1, 2, figsize=(14, 0.42 * len(classes) + 2))
    fig.suptitle("Per attack class (test). Top block = point attacks, bottom block = time-series attacks",
                 fontweight="bold", x=0.01, ha="left")
    for ax, (key, title) in zip(axs, [("detection_rate", "Detected as an attack"), ("recall", "Given the right class")]):
        M = np.array([[val(r, f"test.per_class.{c}.{key}") for r in cols] for c in classes])
        lo = float(np.nanmin(M))
        im = ax.imshow(M, cmap=cmap, vmin=lo, vmax=1.0, aspect="auto")
        ax.set_xticks(range(len(names)), names)
        ax.set_yticks(range(len(classes)), classes)
        ax.grid(False)
        ax.axhline(len([c for c in classes if c in POINT_ATTACKS]) - 0.5, color=SURFACE, lw=3)
        for i in range(len(classes)):
            for j in range(len(names)):
                v = M[i, j]
                if np.isnan(v):
                    continue
                dark = (v - lo) / max(1e-9, 1.0 - lo) > 0.55
                ax.text(j, i, f"{100 * v:.1f}", ha="center", va="center", fontsize=7.5,
                        color=SURFACE if dark else INK)
        ax.set_title(title + " (%)", loc="left")
        fig.colorbar(im, ax=ax, fraction=0.04, format=PercentFormatter(1.0, decimals=0))
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(out_dir / CHART_FILES[5], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[5])


# ---------------------------------------------------------------- main
def parse_args():
    ap = argparse.ArgumentParser(description="SW model window trade-off vs the plain 1-flow model")
    ap.add_argument("--algo", choices=list(NAMES), default="xgboost", help="xgboost (default) or lightgbm")
    ap.add_argument("--windows", type=int, nargs="+", default=None, help=f"default {DEFAULT_WINDOWS}")
    ap.add_argument("--quick", action="store_true", help=f"code check: windows {QUICK_WINDOWS}, 20 trees")
    ap.add_argument("--no-baseline", action="store_true", help="skip the plain 1-flow model")
    ap.add_argument("--drop-bulk", action="store_true", help="train without the 6 bulk features (version leak)")
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=-1, help="threads for TRAINING (-1 = all)")
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto", help="where to TRAIN")
    ap.add_argument("--ram-budget-mb", type=float, default=None, help="optional IoT RAM budget")
    ap.add_argument("--min-pkts-per-s", type=float, default=None, help="optional IoT speed budget")
    ap.add_argument("--plot-only", type=Path, default=None, help="redraw charts + report from a run folder")
    ap.add_argument("--measure-live", nargs=3, type=Path, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.gpu_id, args.gpu_platform = 0, 0               # only used by LightGBM in common.gbm
    set_algo(args.algo, args)
    return args


def finish_outputs(run_dir: Path, results: list[dict], meta: dict, args, log: logging.Logger) -> dict:
    chosen = choose(results, args)
    rows = xgb_vs_sw(results, chosen)
    better = xgb_better_classes(results)
    (run_dir / "WINDOW_TRADEOFF.md").write_text(report(results, chosen, rows, better, meta), encoding="utf-8")
    make_charts(results, chosen, run_dir / "charts", log)
    return {"chosen": chosen, "xgboost_vs_sw": rows, "xgboost_better_classes": better}


def main() -> int:
    args = parse_args()
    if args.measure_live:
        measure_live(*args.measure_live)
        return 0

    if args.plot_only:
        run_dir = args.plot_only.resolve()
        log = setup_logging(run_dir)
        log.info("plot-only: %s", run_dir)
        res = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
        set_algo(res.get("algo", "xgboost"))             # old runs have no "algo": they were XGBoost
        res.update(finish_outputs(run_dir, res["models"], res.get("meta", {}), args, log))
        write_json(run_dir / "results.json", res)
        log.info("FINISHED OK")
        return 0

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{N('run')}_window_tradeoff{'_nobulk' if args.drop_bulk else ''}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    log = setup_logging(run_dir)
    t_start = time.time()
    results: list[dict] = []
    out: dict = {"status": "error", "algo": ALGO, "run_dir": str(run_dir)}
    try:
        np.random.seed(42)
        if args.quick:
            args.trees = 20
        windows = sorted(set(args.windows or (QUICK_WINDOWS if args.quick else DEFAULT_WINDOWS)))
        if windows[0] < 2:
            raise SystemExit("windows must be at least 2 flows (the plain 1-flow model is added automatically)")
        start = max(windows[-1], REF_WINDOW) - 1          # first row every model can score

        from common import config as C
        from common.data import load_meta, load_split
        from common.gbm import _pick_device
        meta = load_meta()
        env = log_environment(log)
        device = _pick_device(ALGO, args)
        config = {"script": SCRIPT_NAME, "algo": ALGO, "drop_bulk": args.drop_bulk,
                  "dropped_features": BULK_FEATURES if args.drop_bulk else [], "windows": windows, "baseline_1flow": not args.no_baseline,
                  "quick": args.quick, "trees": args.trees, "lr": args.lr, "train_threads": args.threads,
                  "train_device": device, "seed": C.SEED, "scored_from_row": start,
                  "point_attacks": POINT_ATTACKS, "series_attacks": SERIES_ATTACKS,
                  "ref_window": REF_WINDOW, "hidden_share": HIDDEN_SHARE, "busy_share": BUSY_SHARE,
                  "start_flows": START_FLOWS, "knee_tol": KNEE_TOL, "live_sample_flows": LIVE_SAMPLE_FLOWS,
                  "live_chunk": LIVE_CHUNK, "live_threads": 1, "ram_budget_mb": args.ram_budget_mb,
                  "min_pkts_per_s": args.min_pkts_per_s, "processed_dir": str(C.PROCESSED_DIR),
                  "processed_data_quick_mode": meta["quick"], "environment": env}
        write_json(run_dir / "config.json", config)
        log.info("settings: algo %s, windows %s, baseline %s, trees %d, train device %s, scored from row %d",
                 ALGO, windows, not args.no_baseline, args.trees, device, start)
        if meta["quick"]:
            log.warning("processed data is from preprocess --quick mode: numbers are NOT real results")

        feats = model_features(meta, args.drop_bulk)
        log.info("model features: %d%s", len(feats), " (6 bulk features dropped)" if args.drop_bulk else "")
        splits = {s: load_split(s) for s in ("train", "val", "test")}
        for s, df in splits.items():
            log.info("%s: %s flows", s, f"{len(df):,}")
        masks = {s: context_masks(df, start) for s, df in splits.items()}

        sample = run_dir / "live_sample.npy"
        np.save(sample, splits["test"][feats].to_numpy(np.float32)[:LIVE_SAMPLE_FLOWS])

        todo = (([] if args.no_baseline else [(N("flat_name"), 1)])
                + [(f"{N('sw_prefix')}_W{w}", w) for w in windows])
        for name, w in todo:
            t0 = time.time()
            r = train_one(name, w, splits, masks, feats, start, args, device, run_dir, log)
            log.info("[%s] live test (1 thread) ...", name)
            r["live"] = run_live(Path(r["model_dir"]), sample, log)
            r["equiv_packets_per_s"] = equiv_pkts(r, meta["avg_packets_per_flow_test"])
            b = r["test"]["binary"]
            log.info("[%s] test F1 %.4f | macro F1 %.4f | false alarms %.2f%% | point %s | series %s | "
                     "RAM %s MB | packets/s %s | %.0f s",
                     name, b["f1"], r["test"]["macro_f1"], 100 * b["false_positive_rate"],
                     fmt(r["test"]["point_right_class"], "pct"), fmt(r["test"]["series_right_class"], "pct"),
                     fmt(g(r, "live.live_peak_ram_mb"), "f0"), fmt(r["equiv_packets_per_s"], "f0"),
                     time.time() - t0)
            results.append(r)
            write_json(run_dir / "results.json", {**out, "models": results})   # keep progress if it crashes
        sample.unlink(missing_ok=True)

        meta_small = {"avg_packets_per_flow_test": meta["avg_packets_per_flow_test"], "quick": meta["quick"],
                      "dropped_features": BULK_FEATURES if args.drop_bulk else []}
        out.update(finish_outputs(run_dir, results, meta_small, args, log))
        out.update({"status": "ok", "meta": meta_small})
        log.info("chosen window: %s | best val F1: %s | best val macro F1: %s",
                 out["chosen"]["chosen_knee"], out["chosen"]["best_val_f1"], out["chosen"]["best_val_macro_f1"])
        log.info("report: %s", run_dir / "WINDOW_TRADEOFF.md")
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    out["models"] = results
    write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.0f s)", out["time_taken_s"])
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
