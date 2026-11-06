"""
Train LightGBM detectors on CICIoT2023 (per-class CSVs in DataSet/CICIoT2023_csv/CSV/<class>/*.csv).

Output of every model: attack yes/no + attack CATEGORY (our 12-category list; CICIoT2023 has 7 of them).
    alert    = predicted category is not "Normal"
    category = the predicted category

Data facts (checked on the header): 39 numeric features, NO label column (the label is the folder name),
one row = statistics of a small group of packets (feature "Number" = packets per row).

Models (choose with --models; default FLAT BAL_MS):
    FLAT    : the current row only (39 features)
    BAL_MS  : row + window 8 stats + window 56 stats + deviation vs window 8 (our chosen design, Phase 1)
    SW_W8, SW_W32, SW_W56 : row + one window (short window-size check)

Time order: CICIoT2023 has one file per attack, like TRUST Lab, so we BUILD a stream per split:
normal rows in file order, with attack BURSTS (200-2000 rows) and SOLO attacks (1-5 rows) inserted.
Split is by row order inside every file (first 70% train, next 15% val, last 15% test): no row is shared.

Also: a leak check (how well ONE feature alone predicts the category; very high = suspicious, e.g. IAT),
per-category / per-class results, hidden attacks, attack start, spill-over false alarms,
single vs series attack groups, balance score, 1-thread model latency per row, model size.

    source /home/abhinav_iot/pqzta-venv/bin/activate
    cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA
    python "MODELS/MODEL CICIOT2023/train_ciciot2023.py" --quick          # small test (~10x fewer rows)
    python "MODELS/MODEL CICIOT2023/train_ciciot2023.py"                  # FLAT + BAL_MS
    python "MODELS/MODEL CICIOT2023/train_ciciot2023.py" --models FLAT BAL_MS SW_W8 SW_W32 SW_W56
    python "MODELS/MODEL CICIOT2023/train_ciciot2023.py" --drop IAT       # if the leak check flags IAT

Saves: runs/train_ciciot2023_<YYYYMMDD_HHMMSS>/
    run.log, config.json, results.json, REPORT.md, leak_check.json, charts/,
    models/<NAME>/model.txt + features.json, confusion_<NAME>.csv, per_class_<NAME>.csv
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import platform
import random
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- settings
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
DATA_DIR = PROJECT_ROOT / "DataSet" / "CICIoT2023_csv" / "CSV"     # files are in CSV/<class>/*.csv
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "train_ciciot2023"
SEED = 42

ROWS_PER_CLASS = 60_000          # max rows per original class (34 classes), spread over its files
BENIGN_ROWS = 1_500_000          # max normal rows
QUICK_FACTOR = 10                # --quick divides both by this
SPLIT = (0.70, 0.15, 0.15)       # by row order inside every file
BURST_LEN = (200, 2000)
SOLO_LEN = (1, 5)
SOLO_SHARE = 0.10                # share of each attack class's rows used as solo attacks

BAL_WINDOWS = (8, 56)
DEV_WINDOW = 8
SW_WINDOWS = (8, 32, 56)
WINDOW_FEATURES = ["Header_Length", "Protocol Type", "Time_To_Live", "Rate", "syn_flag_number",
                   "ack_flag_number", "rst_flag_number", "fin_flag_number", "TCP", "UDP", "ICMP",
                   "Tot sum", "AVG", "Std", "IAT"]

HIDDEN_WINDOW, HIDDEN_MAX_SHARE, SPILL_MIN_SHARE, START_ROWS = 32, 0.25, 0.75, 5

NORMAL = "Normal"
# CICIoT2023 folder -> our category (keys compared in lower case). Mirai rows are floods sent by bots.
CLASS_TO_CATEGORY = {
    "benign_final": NORMAL, "benigntraffic": NORMAL, "benign": NORMAL,
    "ddos-ack_fragmentation": "Flood DoS/DDoS", "ddos-http_flood": "Flood DoS/DDoS",
    "ddos-icmp_flood": "Flood DoS/DDoS", "ddos-icmp_fragmentation": "Flood DoS/DDoS",
    "ddos-pshack_flood": "Flood DoS/DDoS", "ddos-rstfinflood": "Flood DoS/DDoS",
    "ddos-syn_flood": "Flood DoS/DDoS", "ddos-synonymousip_flood": "Flood DoS/DDoS",
    "ddos-tcp_flood": "Flood DoS/DDoS", "ddos-udp_flood": "Flood DoS/DDoS",
    "ddos-udp_fragmentation": "Flood DoS/DDoS", "dos-http_flood": "Flood DoS/DDoS",
    "dos-syn_flood": "Flood DoS/DDoS", "dos-tcp_flood": "Flood DoS/DDoS", "dos-udp_flood": "Flood DoS/DDoS",
    "mirai-greeth_flood": "Flood DoS/DDoS", "mirai-greip_flood": "Flood DoS/DDoS",
    "mirai-udpplain": "Flood DoS/DDoS",
    "ddos-slowloris": "Slow DoS",
    "recon-hostdiscovery": "Scan / Recon", "recon-osscan": "Scan / Recon", "recon-pingsweep": "Scan / Recon",
    "recon-portscan": "Scan / Recon", "vulnerabilityscan": "Scan / Recon",
    "dictionarybruteforce": "Brute force",
    "sqlinjection": "Web attack", "xss": "Web attack", "commandinjection": "Web attack",
    "uploading_attack": "Web attack", "browserhijacking": "Web attack",
    "backdoor_malware": "C2 / Bot",
    "mitm-arpspoofing": "Spoofing / MITM", "dns_spoofing": "Spoofing / MITM",
}
ALL_CATEGORIES = ["Flood DoS/DDoS", "Slow DoS", "Scan / Recon", "Brute force", "Web attack", "Exploit",
                  "C2 / Bot", "Exfiltration", "Spoofing / MITM", "DNS abuse", "TLS attack", "Evasion"]
SINGLE_CATS = {"Web attack", "C2 / Bot", "Exploit", "Exfiltration", "TLS attack", "Evasion"}

LGB_PARAMS = dict(objective="multiclass", learning_rate=0.1, num_leaves=63, min_child_samples=50,
                  feature_fraction=0.9, bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0,
                  verbose=-1, seed=SEED, deterministic=True, force_row_wise=True, device_type="cpu")
NUM_ROUNDS, EARLY_STOP = 2000, 50
LATENCY_ROWS = 2000


# ---------------------------------------------------------------- helpers
def setup_logging(run_dir: Path) -> logging.Logger:
    log = logging.getLogger(SCRIPT_NAME)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    for h in (logging.StreamHandler(sys.stdout), logging.FileHandler(run_dir / "run.log", encoding="utf-8")):
        h.setFormatter(fmt)
        log.addHandler(h)
    return log


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)),
                    encoding="utf-8")


def log_environment(log) -> dict:
    import lightgbm, sklearn
    env = {"python": sys.version.split()[0], "executable": sys.executable, "platform": platform.platform(),
           "lightgbm": lightgbm.__version__, "sklearn": sklearn.__version__, "pandas": pd.__version__,
           "numpy": np.__version__, "cpu_count": os.cpu_count()}
    try:
        import psutil
        env["ram_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
    except Exception:
        pass
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=20)
        env["gpus"] = [l.strip() for l in out.stdout.splitlines() if l.strip()] or "none"
    except Exception as e:
        env["gpus"] = f"not available ({e.__class__.__name__})"
    env["note"] = "LightGBM trains on CPU (its GPU learner crashed in Phase 1)"
    for k, v in env.items():
        log.info("%s: %s", k, v)
    return env


def hmean(*xs: float) -> float:
    return 0.0 if min(xs) <= 0 else len(xs) / sum(1 / x for x in xs)


# ---------------------------------------------------------------- data
def load_data(data_dir: Path, rows_per_class: int, benign_rows: int, log):
    """Returns {split: {class: [DataFrame chunks in file order]}}, feature list, class->category map."""
    if not data_dir.exists():
        raise SystemExit(f"data folder not found: {data_dir}")
    parts = {s: {} for s in ("train", "val", "test")}
    features, class_cat, counts = None, {}, {}
    # find CSVs at any depth; the class = the folder that holds the file (case-insensitive ".csv")
    all_csv = sorted(p for p in data_dir.rglob("*") if p.is_file() and p.suffix.lower() == ".csv")
    by_folder: dict = {}
    for p in all_csv:
        by_folder.setdefault(p.parent, []).append(p)
    top = sorted(p.name for p in data_dir.iterdir())
    log.info("found %d CSV files in %d folders under %s (top level has %d entries: %s)",
             len(all_csv), len(by_folder), data_dir, len(top), top[:8])
    if not all_csv:
        others = sorted({p.suffix for p in data_dir.rglob("*") if p.is_file()})
        raise SystemExit(f"no .csv files under {data_dir}; file endings found there: {others or 'none'}")
    for folder in sorted(by_folder):
        cat = CLASS_TO_CATEGORY.get(folder.name.lower())
        if cat is None:
            log.warning("unknown class folder %s: skipped (add it to CLASS_TO_CATEGORY)", folder.name)
            continue
        files = sorted(by_folder[folder])
        cap = benign_rows if cat == NORMAL else rows_per_class
        per_file = math.ceil(cap / len(files))
        n_class = 0
        for f in files:
            df = pd.read_csv(f, nrows=per_file, dtype=np.float32)
            df.columns = [c.strip() for c in df.columns]
            if features is None:
                features = list(df.columns)
            if list(df.columns) != features:
                raise SystemExit(f"{f}: columns differ from the first file")
            df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
            df["cls"] = folder.name
            n = len(df)
            a, b = int(SPLIT[0] * n), int((SPLIT[0] + SPLIT[1]) * n)
            for s, chunk in (("train", df.iloc[:a]), ("val", df.iloc[a:b]), ("test", df.iloc[b:])):
                if len(chunk):
                    parts[s].setdefault(folder.name, []).append(chunk)
            n_class += n
        class_cat[folder.name] = cat
        counts[folder.name] = n_class
        log.info("   %-28s %-16s %2d files, %9s rows used", folder.name, cat, len(files), f"{n_class:,}")
    if features is None:
        raise SystemExit("CSV files found, but none in a known class folder (see warnings above)")
    if NORMAL not in class_cat.values():
        raise SystemExit("no Benign folder found: cannot build normal traffic")
    return parts, features, class_cat, counts


def build_stream(split_parts: dict, class_cat: dict, rng, solo_share: float) -> pd.DataFrame:
    """Normal rows in order with attack bursts and solo attacks inserted at random places."""
    pool_list, offsets, start = [], {}, 0
    for cls, chunks in split_parts.items():
        df = pd.concat(chunks, ignore_index=True)
        pool_list.append(df)
        offsets[cls] = (start, start + len(df))
        start += len(df)
    pool = pd.concat(pool_list, ignore_index=True)

    segs = []                                                  # (start, end, kind) kind 1 = burst, 2 = solo
    for cls, (s, e) in offsets.items():
        if class_cat[cls] == NORMAL:
            continue
        n_solo = int((e - s) * solo_share)
        i = s
        while i < s + n_solo:
            k = int(rng.integers(SOLO_LEN[0], SOLO_LEN[1] + 1))
            segs.append((i, min(i + k, s + n_solo), 2))
            i += k
        i = s + n_solo
        while i < e:
            k = int(rng.integers(BURST_LEN[0], BURST_LEN[1] + 1))
            segs.append((i, min(i + k, e), 1))
            i += k
    segs = [segs[j] for j in rng.permutation(len(segs))]

    normal_ranges = [offsets[c] for c in offsets if class_cat[c] == NORMAL]
    normal_idx = np.concatenate([np.arange(s, e) for s, e in normal_ranges])
    cuts = np.sort(rng.integers(0, len(normal_idx) + 1, size=len(segs)))
    bounds = np.concatenate([[0], cuts, [len(normal_idx)]])

    idx, kind, pos, burst = [], [], [], []
    for j in range(len(segs) + 1):
        piece = normal_idx[bounds[j]:bounds[j + 1]]
        idx.append(piece); kind.append(np.zeros(len(piece), np.int8))
        pos.append(np.full(len(piece), -1, np.int32)); burst.append(np.full(len(piece), -1, np.int32))
        if j < len(segs):
            s, e, k = segs[j]
            idx.append(np.arange(s, e)); kind.append(np.full(e - s, k, np.int8))
            pos.append(np.arange(e - s, dtype=np.int32)); burst.append(np.full(e - s, j, np.int32))
    stream = pool.iloc[np.concatenate(idx)].reset_index(drop=True)
    stream["seg_kind"] = np.concatenate(kind)
    stream["pos_in_seg"] = np.concatenate(pos)
    stream["seg_id"] = np.concatenate(burst)
    stream["category"] = stream["cls"].map(class_cat)
    return stream


def window_block(W: pd.DataFrame, w: int) -> pd.DataFrame:
    r = W.rolling(w, min_periods=1)
    return pd.concat([r.mean().add_suffix(f"_w{w}_mean"), r.std(ddof=0).add_suffix(f"_w{w}_std"),
                      r.min().add_suffix(f"_w{w}_min"), r.max().add_suffix(f"_w{w}_max")], axis=1)


def build_X(stream: pd.DataFrame, base: list[str], wfeats: list[str], model: str) -> pd.DataFrame:
    X = stream[base]
    W = stream[wfeats].astype(np.float64)
    blocks = [X]
    if model == "BAL_MS":
        for w in BAL_WINDOWS:
            blocks.append(window_block(W, w))
        r = W.rolling(DEV_WINDOW, min_periods=1)
        blocks.append(((W - r.mean()) / (r.std(ddof=0) + 1e-6)).add_suffix(f"_dev{DEV_WINDOW}"))
    elif model.startswith("SW_W"):
        blocks.append(window_block(W, int(model[4:])))
    elif model != "FLAT":
        raise ValueError(model)
    return pd.concat(blocks, axis=1).fillna(0).astype(np.float32)


def context(stream: pd.DataFrame) -> dict:
    att = (stream["category"] != NORMAL).to_numpy()
    share = pd.Series(att.astype(np.float32)).rolling(HIDDEN_WINDOW, min_periods=1).mean().to_numpy()
    return {"attack": att,
            "hidden": att & (share < HIDDEN_MAX_SHARE),
            "start": att & (stream["seg_kind"].to_numpy() == 1) & (stream["pos_in_seg"].to_numpy() < START_ROWS),
            "spill": ~att & (share >= SPILL_MIN_SHARE)}


# ---------------------------------------------------------------- leak check
def leak_check(train: pd.DataFrame, val: pd.DataFrame, feats: list[str], cats: list[str], log) -> list[dict]:
    import lightgbm as lgb
    from sklearn.metrics import f1_score
    rng = np.random.default_rng(SEED)
    tr = train.iloc[rng.choice(len(train), min(len(train), 200_000), replace=False)]
    va = val.iloc[rng.choice(len(val), min(len(val), 100_000), replace=False)]
    ytr, yva = tr["category"].map(cats.index).to_numpy(), va["category"].map(cats.index).to_numpy()
    params = {**LGB_PARAMS, "num_class": len(cats), "num_leaves": 15, "num_threads": os.cpu_count() or 4}
    rows = []
    for f in feats:
        b = lgb.train(params, lgb.Dataset(tr[[f]], ytr), num_boost_round=50)
        pred = b.predict(va[[f]]).argmax(1)
        rows.append({"feature": f, "macro_f1_alone": round(float(f1_score(yva, pred, average="macro")), 4),
                     "accuracy_alone": round(float((pred == yva).mean()), 4),
                     "distinct_values": int(train[f].nunique())})
    rows.sort(key=lambda r: -r["macro_f1_alone"])
    log.info("leak check (one feature alone -> category, val macro F1), top 10:")
    for r in rows[:10]:
        log.info("   %-16s F1 %.3f  acc %.3f  distinct %s", r["feature"], r["macro_f1_alone"],
                 r["accuracy_alone"], f"{r['distinct_values']:,}")
    return rows


# ---------------------------------------------------------------- train + evaluate
def class_weights(y: np.ndarray, k: int) -> np.ndarray:
    cnt = np.bincount(y, minlength=k).astype(np.float64)
    w = np.where(cnt > 0, (len(y) / (k * np.maximum(cnt, 1))) ** 0.5, 0.0)     # soft balance (sqrt)
    return w[y]


def evaluate(y: np.ndarray, proba: np.ndarray, cats: list[str], ctx: dict, stream: pd.DataFrame) -> dict:
    from sklearn.metrics import f1_score
    pred = proba.argmax(1)
    normal_id = cats.index(NORMAL)
    alert = pred != normal_id
    att = ctx["attack"]
    tp, fp = int((alert & att).sum()), int((alert & ~att).sum())
    fn, tn = int((~alert & att).sum()), int((~alert & ~att).sum())
    det = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    prec = tp / max(tp + fp, 1)
    right = pred == y
    single = att & stream["category"].isin(SINGLE_CATS).to_numpy()
    series = att & ~stream["category"].isin(SINGLE_CATS).to_numpy()
    res = {
        "detection_rate": det, "false_alarm_rate": fpr, "precision": prec,
        "f1_attack": 2 * prec * det / max(prec + det, 1e-12),
        "category_macro_f1": float(f1_score(y, pred, average="macro")),
        "category_accuracy": float(right.mean()),
        "hidden_detection": float(alert[ctx["hidden"]].mean()) if ctx["hidden"].any() else None,
        "attack_start_detection": float(alert[ctx["start"]].mean()) if ctx["start"].any() else None,
        "spill_false_alarm_rate": float(alert[ctx["spill"]].mean()) if ctx["spill"].any() else None,
        "single_right_category": float(right[single].mean()) if single.any() else None,
        "series_right_category": float(right[series].mean()) if series.any() else None,
        "n_hidden": int(ctx["hidden"].sum()), "n_start": int(ctx["start"].sum()), "n_spill": int(ctx["spill"].sum()),
        "missed_attacks": fn, "false_alarms": fp,
        "per_category_recall": {c: float(right[y == i].mean()) for i, c in enumerate(cats) if (y == i).any()},
    }
    parts = [v for v in (res["hidden_detection"], res["single_right_category"], res["series_right_category"])
             if v is not None]
    res["balance_score"] = hmean(*parts) if parts else None
    return res


def latency_us(booster, X: pd.DataFrame) -> dict:
    rows = X.to_numpy()[: min(LATENCY_ROWS, len(X))]
    for i in range(min(50, len(rows))):                           # warm-up
        booster.predict(rows[i:i + 1], num_threads=1)
    t = []
    for i in range(len(rows)):
        t0 = time.perf_counter()
        booster.predict(rows[i:i + 1], num_threads=1)
        t.append((time.perf_counter() - t0) * 1e6)
    t = np.array(t)
    return {"model_us_per_row_median": float(np.median(t)), "model_us_per_row_p99": float(np.percentile(t, 99)),
            "max_rows_per_s_1thread": float(1e6 / np.median(t))}


def train_one(name, streams, base, wfeats, cats, run_dir, log) -> dict:
    import lightgbm as lgb
    t0 = time.time()
    X = {s: build_X(streams[s], base, wfeats, name) for s in streams}
    y = {s: streams[s]["category"].map(cats.index).to_numpy() for s in streams}
    log.info("[%s] %d inputs, train %s rows, build %.0f s", name, X["train"].shape[1], f"{len(X['train']):,}",
             time.time() - t0)
    params = {**LGB_PARAMS, "num_class": len(cats), "num_threads": os.cpu_count() or 4}
    dtr = lgb.Dataset(X["train"], y["train"], weight=class_weights(y["train"], len(cats)), free_raw_data=True)
    dva = lgb.Dataset(X["val"], y["val"], weight=class_weights(y["val"], len(cats)), reference=dtr)
    t1 = time.time()
    booster = lgb.train(params, dtr, NUM_ROUNDS, valid_sets=[dva], valid_names=["val"],
                        callbacks=[lgb.early_stopping(EARLY_STOP, verbose=False), lgb.log_evaluation(100)])
    train_s = time.time() - t1
    mdir = run_dir / "models" / name
    mdir.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(mdir / "model.txt"), num_iteration=booster.best_iteration)
    write_json(mdir / "features.json", {"model": name, "inputs": list(X["train"].columns), "base_features": base,
                                        "window_features": wfeats, "categories": cats,
                                        "bal_windows": BAL_WINDOWS, "dev_window": DEV_WINDOW})
    out = {"model": name, "n_inputs": X["train"].shape[1], "best_iteration": booster.best_iteration,
           "train_seconds": round(train_s, 1), "model_file_mb": round((mdir / "model.txt").stat().st_size / 1e6, 2)}
    for s in ("val", "test"):
        proba = booster.predict(X[s], num_iteration=booster.best_iteration)
        out[s] = evaluate(y[s], proba, cats, context(streams[s]), streams[s])
        if s == "test":
            from sklearn.metrics import confusion_matrix
            pred = proba.argmax(1)
            cm = confusion_matrix(y[s], pred, labels=range(len(cats)))
            pd.DataFrame(cm, index=[f"true {c}" for c in cats], columns=[f"pred {c}" for c in cats]) \
                .to_csv(run_dir / f"confusion_{name}.csv")
            st = streams[s]
            pc = pd.DataFrame({"cls": st["cls"], "category": st["category"],
                               "alert": pred != cats.index(NORMAL), "right": pred == y[s]})
            pc.groupby(["cls", "category"]).agg(rows=("alert", "size"), alerted=("alert", "mean"),
                                                right_category=("right", "mean")) \
                .reset_index().to_csv(run_dir / f"per_class_{name}.csv", index=False)
    out["live"] = latency_us(booster, X["test"])
    t = out["test"]
    log.info("[%s] TEST detection %.2f%% | false alarms %.2f%% | category macro F1 %.4f | hidden %.2f%% | "
             "start %s | single right %s | series right %s | balance %s | %.0f us/row (1 thread) | %.1f MB",
             name, 100 * t["detection_rate"], 100 * t["false_alarm_rate"], t["category_macro_f1"],
             100 * (t["hidden_detection"] or 0), fmt_pct(t["attack_start_detection"]),
             fmt_pct(t["single_right_category"]), fmt_pct(t["series_right_category"]),
             fmt_pct(t["balance_score"]), out["live"]["model_us_per_row_median"], out["model_file_mb"])
    return out


def fmt_pct(v) -> str:
    return "n/a" if v is None else f"{100 * v:.2f}%"


# ---------------------------------------------------------------- report
def make_chart(results: dict, run_dir: Path, log) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    keys = [("detection_rate", "Detection"), ("hidden_detection", "Hidden attacks"),
            ("single_right_category", "Single: right cat."), ("series_right_category", "Series: right cat."),
            ("category_macro_f1", "Category macro F1"), ("false_alarm_rate", "False alarms")]
    names = list(results)
    fig, ax = plt.subplots(figsize=(11, 4.5))
    width = 0.8 / max(len(names), 1)
    for i, n in enumerate(names):
        vals = [100 * (results[n]["test"].get(k) or 0) for k, _ in keys]
        ax.bar(np.arange(len(keys)) + i * width, vals, width, label=n)
    ax.set_xticks(np.arange(len(keys)) + width * (len(names) - 1) / 2)
    ax.set_xticklabels([l for _, l in keys])
    ax.set_ylabel("% (test)")
    ax.set_title("CICIoT2023: models on the test stream")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    (run_dir / "charts").mkdir(exist_ok=True)
    fig.savefig(run_dir / "charts" / "01_models.png", dpi=130)
    plt.close(fig)
    log.info("chart saved: %s", run_dir / "charts" / "01_models.png")


def write_report(run_dir: Path, results: dict, leak: list, counts: dict, class_cat: dict, cats: list,
                 dropped: list, sizes: dict) -> None:
    L = ["# CICIoT2023: LightGBM training results", "",
         "Output: attack yes/no + category. Streams are built (normal rows + attack bursts 200-2000 rows + "
         "solo attacks 1-5 rows). Split by row order inside every file.", "",
         f"Stream rows: train {sizes['train']:,}, val {sizes['val']:,}, test {sizes['test']:,}. "
         f"Dropped features: {', '.join(dropped) or 'none'}.", "",
         "## 1. Test results", "",
         "| Model | Inputs | Detection | False alarms | Category macro F1 | Hidden attacks | Attack start | "
         "Single right cat. | Series right cat. | Balance | µs/row (1 thread) | Model MB |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for n, r in results.items():
        t = r["test"]
        L.append(f"| {n} | {r['n_inputs']} | {fmt_pct(t['detection_rate'])} | {fmt_pct(t['false_alarm_rate'])} | "
                 f"{t['category_macro_f1']:.4f} | {fmt_pct(t['hidden_detection'])} | "
                 f"{fmt_pct(t['attack_start_detection'])} | {fmt_pct(t['single_right_category'])} | "
                 f"{fmt_pct(t['series_right_category'])} | {fmt_pct(t['balance_score'])} | "
                 f"{r['live']['model_us_per_row_median']:.0f} | {r['model_file_mb']} |")
    L += ["", "µs/row = model only; the window features (BAL_MS, SW) need a live builder at the gateway.", "",
          "## 2. Per category (test, share with the right category)", "",
          "| Category | " + " | ".join(results) + " |", "|---|" + "---|" * len(results)]
    for c in cats:
        L.append(f"| {c} | " + " | ".join(fmt_pct(results[n]["test"]["per_category_recall"].get(c))
                                          for n in results) + " |")
    missing = [c for c in ALL_CATEGORIES if c not in cats]
    L += ["", f"Categories NOT in CICIoT2023 (need another dataset): {', '.join(missing)}.", "",
          "## 3. Leak check (one feature alone -> category)", "",
          "Very high values for a feature that should not identify an attack (for example IAT, a time value) "
          "mean a leak: retrain with `--drop <feature>`.", "",
          "| Feature | Macro F1 alone | Accuracy alone | Distinct values |", "|---|---|---|---|"]
    for r in leak[:15]:
        L.append(f"| {r['feature']} | {r['macro_f1_alone']:.3f} | {r['accuracy_alone']:.3f} | "
                 f"{r['distinct_values']:,} |")
    L += ["", "## 4. Classes used", "", "| CICIoT2023 class | Category | Rows used |", "|---|---|---|"]
    for c, n in counts.items():
        L.append(f"| {c} | {class_cat[c]} | {n:,} |")
    L += ["", "## 5. Charts", "", "![models](charts/01_models.png)", "",
          "Files: confusion_<MODEL>.csv, per_class_<MODEL>.csv, models/<MODEL>/model.txt + features.json."]
    (run_dir / "REPORT.md").write_text("\n".join(L) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Train LightGBM on CICIoT2023 (attack + category)")
    ap.add_argument("--models", nargs="+", default=["FLAT", "BAL_MS"],
                    choices=["FLAT", "BAL_MS"] + [f"SW_W{w}" for w in SW_WINDOWS])
    ap.add_argument("--drop", nargs="*", default=[], help="features to remove (e.g. IAT)")
    ap.add_argument("--quick", action="store_true", help=f"{QUICK_FACTOR}x fewer rows (test run)")
    ap.add_argument("--skip-leak-check", action="store_true")
    ap.add_argument("--data", type=Path, default=DATA_DIR)
    args = ap.parse_args()

    random.seed(SEED)
    np.random.seed(SEED)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    log = setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    try:
        env = log_environment(log)
        rows_cls = ROWS_PER_CLASS // (QUICK_FACTOR if args.quick else 1)
        rows_ben = BENIGN_ROWS // (QUICK_FACTOR if args.quick else 1)
        config = {"script": SCRIPT_NAME, "data": str(args.data), "models": args.models, "drop": args.drop,
                  "quick": args.quick, "rows_per_class": rows_cls, "benign_rows": rows_ben, "split": SPLIT,
                  "burst_len": BURST_LEN, "solo_len": SOLO_LEN, "solo_share": SOLO_SHARE,
                  "bal_windows": BAL_WINDOWS, "dev_window": DEV_WINDOW, "window_features": WINDOW_FEATURES,
                  "lgb_params": LGB_PARAMS, "num_rounds": NUM_ROUNDS, "early_stop": EARLY_STOP, "seed": SEED,
                  "class_to_category": CLASS_TO_CATEGORY, "environment": env}
        write_json(run_dir / "config.json", config)
        log.info("settings: models %s | drop %s | rows/class %s | benign %s | quick %s", args.models, args.drop,
                 f"{rows_cls:,}", f"{rows_ben:,}", args.quick)

        log.info("loading %s", args.data)
        parts, features, class_cat, counts = load_data(args.data, rows_cls, rows_ben, log)
        bad = [d for d in args.drop if d not in features]
        if bad:
            raise SystemExit(f"--drop: unknown feature(s) {bad}; features are {features}")
        base = [f for f in features if f not in args.drop]
        wfeats = [f for f in WINDOW_FEATURES if f in base]
        cats = [NORMAL] + [c for c in ALL_CATEGORIES if c in set(class_cat.values())]
        log.info("%d features (%d used), %d classes -> %d categories: %s", len(features), len(base),
                 len(class_cat), len(cats), cats)

        streams = {}
        for k, s in enumerate(("train", "val", "test")):
            streams[s] = build_stream(parts[s], class_cat, np.random.default_rng(SEED + k), SOLO_SHARE)
            vc = streams[s]["category"].value_counts()
            log.info("%s stream: %s rows (%.1f%% attack) | %s", s, f"{len(streams[s]):,}",
                     100 * (1 - vc.get(NORMAL, 0) / len(streams[s])), dict(vc))
        del parts
        sizes = {s: len(streams[s]) for s in streams}

        leak = [] if args.skip_leak_check else leak_check(streams["train"], streams["val"], base, cats, log)
        write_json(run_dir / "leak_check.json", leak)

        results = {}
        for m in args.models:
            results[m] = train_one(m, streams, base, wfeats, cats, run_dir, log)
            write_json(run_dir / "results.json", {**out, "models": results})     # save progress
        make_chart(results, run_dir, log)
        write_report(run_dir, results, leak, counts, class_cat, cats, args.drop, sizes)
        out.update(status="ok", models=results, categories=cats, features_used=base, dropped=args.drop,
                   stream_rows=sizes, rows_per_class_used=counts,
                   leak_check_top5=leak[:5], report=str(run_dir / "REPORT.md"))
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("report: %s", out["report"])
        log.info("FINISHED OK (%.1f min)", out["time_taken_s"] / 60)
        return 0
    log.error("FINISHED WITH ERROR")
    return 1


if __name__ == "__main__":
    sys.exit(main())
