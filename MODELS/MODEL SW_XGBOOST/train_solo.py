"""
Train a new SW-XGBoost on a stream that also has SOLO attacks, and compare it with the old models.

    python "MODEL SW_XGBOOST/train_solo.py"
    python "MODEL SW_XGBOOST/train_solo.py" --solo-share 0.10 --other-share 0.03

Why: in the old training stream every attack came in a burst of 200-2,000 flows, so the
model learned to trust the window and missed attacks hidden among normal flows
(Exploitation 54%, BufferOverflow 70% when the window was mostly normal).

What is new (labels are used ONLY to build the training stream, never as model input):
  * Solo units: some flows of every attack class are put in ALONE or in tiny groups
    (1-5 flows), with at least `--solo-gap` normal flows on each side. "Solo-type" classes
    (one-shot attacks such as exploits) get a bigger share than group-type classes, but
    every class gets some, so the model cannot learn "class X is always alone".
  * Optional deviation features (--no-deviation to switch off): for the window statistic
    features, how far the current flow is from its window average, in window standard
    deviations. A solo attack then stands out instead of being averaged away.

Models compared (same rules for all: CPU prediction, same test rows per test set):
  FLAT         plain XGBoost                      MODEL XGBOOST/output
  SW_OLD       your current SW-XGBoost            MODEL SW_XGBOOST/output
  SW_SOLO      new stream                         trained here
  SW_SOLO_DEV  new stream + deviation features    trained here

Test sets:
  TEST_ORIGINAL  the old test stream (data/processed/test.parquet), unchanged
  TEST_SOLO      a new stream from the SAME test flows, with many solo attacks
                 (the new models were trained on this kind of stream, the old ones were not;
                  that is the point of the test, and it is said in the report)

The flows of each split are taken back out of the existing train/val/test streams, so no
test flow is ever used for training. Within each class the flows keep their burst order.
Saves: MODEL SW_XGBOOST/solo_training/<model>/ and results/SOLO_TRAINING.md (+ .json)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common import config as C                                          # noqa: E402
from common.bench import PeakMemory, timed                              # noqa: E402
from common.data import load_meta, load_split                           # noqa: E402
from common.gbm import _class_weights, _make_model, _pick_device        # noqa: E402
from common.metrics import evaluate                                     # noqa: E402
from common.windows import flow_only_features, sliding_window_features  # noqa: E402

OUT = HERE / "solo_training"
B = C.CLASS_TO_ID[C.BENIGN]
# one-shot attacks: a single request or connection can be the whole attack
SOLO_TYPE = ["Exploitation", "BufferOverflow", "WebBased", "API", "TLSSSL", "C2Beaconing", "Exfiltration"]
QUIET = ["Exploitation", "BufferOverflow", "Bruteforce", "C2Beaconing"]


# ---------------------------------------------------------------- stream building

def class_parts(split: str) -> dict[str, pd.DataFrame]:
    """The flows of one split, per class, taken back out of the existing stream."""
    df = load_split(split)
    feats = [c for c in df.columns if c not in ("label", "burst")]
    return {c: df.loc[df["label"] == C.CLASS_TO_ID[c], feats].reset_index(drop=True)
            for c in C.CLASSES if (df["label"] == C.CLASS_TO_ID[c]).any()}


def build_mixed_stream(parts: dict[str, pd.DataFrame], rng: np.random.Generator,
                       solo_share: float, other_share: float, solo_gap: int) -> pd.DataFrame:
    """Normal traffic with attack BURSTS (as before) plus SOLO units of 1-5 attack flows.

    Bursts: BURST_MIN..BURST_MAX attack flows with some normal flows mixed in (like
    common/stream.py). Solo units: 1-5 attack flows next to each other, with at least
    `solo_gap` normal flows before and after, so the window around them is mostly normal.
    """
    benign = parts[C.BENIGN]
    cols = list(benign.columns)
    units = []                                    # (kind, class, start, end)
    for cls, df in parts.items():
        if cls == C.BENIGN:
            continue
        n = len(df)
        n_solo = int(n * (solo_share if cls in SOLO_TYPE else other_share))
        pos = 0
        while pos < n_solo:                       # first part of the class -> solo units
            L = min(int(rng.integers(1, 6)), n_solo - pos)
            units.append(("solo", cls, pos, pos + L)); pos += L
        while pos < n:                            # the rest -> bursts
            L = min(int(rng.integers(C.BURST_MIN, C.BURST_MAX + 1)), n - pos)
            units.append(("burst", cls, pos, pos + L)); pos += L
    units = [units[i] for i in rng.permutation(len(units))]

    # normal flows: inside bursts, the fixed gap around solos, and random extra gaps
    nb = len(benign)
    inside = np.zeros(len(units), np.int64)
    for i, (kind, _, s, e) in enumerate(units):
        if kind == "burst":
            p = rng.uniform(C.ATTACK_SHARE_MIN, C.ATTACK_SHARE_MAX)
            inside[i] = int((e - s) * (1 - p) / p)
    fixed = solo_gap * len(units)                 # every unit gets >= solo_gap normal flows before it
    budget = nb - fixed - solo_gap
    if budget <= 0:
        raise SystemExit(f"not enough normal flows ({nb:,}) for {len(units):,} units with gap {solo_gap}; "
                         "lower --solo-share / --other-share / --solo-gap")
    if inside.sum() > budget * (1 - C.BACKGROUND_SHARE):
        inside = (inside * (budget * (1 - C.BACKGROUND_SHARE) / inside.sum())).astype(np.int64)
    extra = budget - int(inside.sum())
    cuts = np.sort(rng.integers(0, extra + 1, size=len(units)))
    gaps = np.diff(np.concatenate([[0], cuts, [extra]])) + solo_gap

    offsets, mats, off = {}, [], 0
    for cls, df in parts.items():
        offsets[cls] = off; mats.append(df[cols].to_numpy(np.float32)); off += len(df)
    big = np.concatenate(mats)
    b_off = offsets[C.BENIGN]

    idx_parts, lab_parts, unit_parts, kind_parts = [], [], [], []
    bp = 0

    def add_benign(k: int):
        nonlocal bp
        k = int(min(k, nb - bp))
        idx_parts.append(b_off + np.arange(bp, bp + k)); bp += k
        lab_parts.append(np.full(k, B, np.int8)); unit_parts.append(np.full(k, -1, np.int32))
        kind_parts.append(np.zeros(k, np.int8))

    for u, ((kind, cls, s, e), g, m) in enumerate(zip(units, gaps[:-1], inside)):
        add_benign(g)
        L = e - s
        m = int(min(m, nb - bp))
        is_att = np.zeros(L + m, bool)
        is_att[rng.choice(L + m, size=L, replace=False) if m else np.arange(L)] = True
        idx = np.empty(L + m, np.int64)
        idx[is_att] = offsets[cls] + np.arange(s, e)
        idx[~is_att] = b_off + np.arange(bp, bp + m); bp += m
        idx_parts.append(idx)
        lab_parts.append(np.where(is_att, C.CLASS_TO_ID[cls], B).astype(np.int8))
        unit_parts.append(np.where(is_att, u, -1).astype(np.int32))
        kind_parts.append(np.where(is_att, 2 if kind == "solo" else 1, 0).astype(np.int8))
    add_benign(nb - bp)

    out = pd.DataFrame(big[np.concatenate(idx_parts)], columns=cols)
    out["label"] = np.concatenate(lab_parts)
    out["burst"] = np.concatenate(unit_parts)
    out["unit_kind"] = np.concatenate(kind_parts)     # 0 normal, 1 burst attack, 2 solo attack
    return out


# ---------------------------------------------------------------- features

def deviation_features(df: pd.DataFrame, window: int) -> tuple[np.ndarray, list[str]]:
    """(current value - window mean) / window std, for each window statistic feature."""
    feats = [f for f in C.WINDOW_STAT_FEATURES if f in df.columns]
    r = df[feats].rolling(window, min_periods=window)
    z = (df[feats] - r.mean()) / (r.std() + 1e-6)
    X = z.to_numpy(np.float32)[window - 1:].copy()      # pandas may return a read-only view
    X[~np.isfinite(X)] = 0.0
    return X, [f"dev_{f}" for f in feats]


def model_inputs(df: pd.DataFrame, feats: list[str], window: int, kind: str) -> np.ndarray:
    if kind == "flat":
        return flow_only_features(df, feats, window)[0]
    X, _ = sliding_window_features(df, feats, window)
    if kind == "sw_dev":
        X = np.hstack([X, deviation_features(df, window)[0]])
    return X


def labels_of(df: pd.DataFrame, window: int):
    sl = slice(window - 1, None)
    kind = df["unit_kind"].to_numpy()[sl] if "unit_kind" in df else None
    return df["label"].to_numpy(np.int64)[sl], df["burst"].to_numpy(np.int64)[sl], kind


# ---------------------------------------------------------------- models

def load_model(model_dir: Path):
    info = json.loads((model_dir / "model_info.json").read_text(encoding="utf-8"))
    booster = xgb.Booster()
    booster.load_model(str(model_dir / info["model_file"]))
    booster.set_param({"device": "cpu"})
    ids = np.array([C.CLASS_TO_ID[c] for c in info["classes"]])
    return booster, ids, info


def train_new(name: str, kind: str, streams: dict, feats: list[str], window: int, args, device: str) -> dict:
    perf: dict = {}
    with PeakMemory() as mem:
        Xtr = model_inputs(streams["train"], feats, window, kind)
        ytr, _, _ = labels_of(streams["train"], window)
        Xva = model_inputs(streams["val"], feats, window, kind)
        yva, _, _ = labels_of(streams["val"], window)
        present = np.unique(ytr)
        ytr_l = np.searchsorted(present, ytr)
        keep = np.isin(yva, present)
        model = _make_model("xgboost", len(present), args, device)
        print(f"   [{name}] training on {len(Xtr):,} rows, {Xtr.shape[1]} features, {device} ...")
        with timed(perf, "train_time_s"):
            model.fit(Xtr, ytr_l, sample_weight=_class_weights(ytr_l),
                      eval_set=[(Xva[keep], np.searchsorted(present, yva[keep]))], verbose=False)
    out = OUT / name
    out.mkdir(parents=True, exist_ok=True)
    model.save_model(out / "model.json")
    (out / "model_info.json").write_text(json.dumps({
        "name": name, "algo": "xgboost", "windowed": True, "window": window,
        "deviation_features": kind == "sw_dev", "model_file": "model.json",
        "base_features": feats, "classes": [C.CLASSES[i] for i in present],
        "trained_on": "solo + burst stream (train_solo.py)",
    }, indent=2), encoding="utf-8")
    return {"train_time_s": perf["train_time_s"], "train_peak_ram_mb": mem.peak_mb,
            "best_iteration": getattr(model, "best_iteration", None), "n_features": int(Xtr.shape[1])}


def score(models: dict, stream: pd.DataFrame, feats: list[str], window: int) -> dict:
    y, burst, unit_kind = labels_of(stream, window)
    att = y != B
    lab_all = stream["label"].to_numpy() != B
    share = pd.Series(lab_all.astype(np.float32)).rolling(window).mean().to_numpy()[window - 1:]
    low = share < 0.25
    pos = np.full(len(y), -1)
    m = burst >= 0
    s = pd.Series(burst[m])
    pos[m] = s.groupby(s).cumcount().to_numpy()
    start = m & (pos < 5)
    busy = (~att) & (share >= 0.75)
    solo = (unit_kind == 2) if unit_kind is not None else np.zeros(len(y), bool)

    res, X_cache = {}, {}
    for name, (booster, ids, kind) in models.items():
        if kind not in X_cache:
            X_cache[kind] = model_inputs(stream, feats, window, kind)
        X = X_cache[kind]
        t0 = time.perf_counter()
        pred = ids[booster.predict(xgb.DMatrix(X)).reshape(len(X), -1).argmax(1)]
        pred_s = time.perf_counter() - t0
        e = evaluate(y, pred, burst)
        hit = pred != B
        res[name] = {
            "binary": e["binary"], "macro_f1": e["macro_f1"],
            "hidden_detection": float(hit[att & low].mean()) if (att & low).any() else None,
            "solo_unit_detection": float(hit[solo].mean()) if solo.any() else None,
            "start_detection": float(hit[start].mean()) if start.any() else None,
            "spillover_false_alarm": float(hit[busy].mean()) if busy.any() else None,
            "quiet_hidden": {c: (float(hit[(y == C.CLASS_TO_ID[c]) & low].mean())
                                 if ((y == C.CLASS_TO_ID[c]) & low).any() else None) for c in QUIET},
            "predict_flows_per_s": len(X) / pred_s,
        }
    res["_counts"] = {"flows": int(len(y)), "hidden": int((att & low).sum()), "solo_units": int(solo.sum()),
                      "start": int(start.sum()), "busy_normal": int(busy.sum())}
    return res


# ---------------------------------------------------------------- report

def pct(v) -> str:
    return "–" if v is None else f"{100 * v:.2f}%"


def report(tests: dict, train_info: dict, args) -> str:
    L = ["# SW-XGBoost trained with solo attacks (TRUST Lab)", "",
         f"New training stream: solo-type classes {args.solo_share:.0%} solo, other classes "
         f"{args.other_share:.0%} solo, solo units of 1-5 flows with at least {args.solo_gap} normal flows around them.",
         f"Solo-type classes: {', '.join(SOLO_TYPE)}.", ""]
    for tname, res in tests.items():
        c = res["_counts"]
        models = [k for k in res if not k.startswith("_")]
        L += [f"## {tname}", "",
              f"{c['flows']:,} flows. Hidden attacks (window < 25% attack): {c['hidden']:,}. "
              f"Solo-unit attack flows: {c['solo_units']:,}. Attack-start flows: {c['start']:,}. "
              f"Normal flows in a 75%+ attack window: {c['busy_normal']:,}.", "",
              "| Model | F1 | Detection rate | False alarm rate | Missed attacks | False alarms | Macro F1 |",
              "|---|---|---|---|---|---|---|"]
        for m in models:
            b = res[m]["binary"]
            L.append(f"| {m} | {b['f1']:.4f} | {pct(b['recall_detection_rate'])} | {pct(b['false_positive_rate'])} "
                     f"| {b['fn']:,} | {b['fp']:,} | {res[m]['macro_f1']:.4f} |")
        L += ["", "| Model | Hidden attacks detected | Solo-unit attacks detected | Attack start detected | Spill-over false alarms | "
              + " | ".join(f"{q} hidden" for q in QUIET) + " |",
              "|---|---|---|---|---|" + "---|" * len(QUIET)]
        for m in models:
            r = res[m]
            L.append(f"| {m} | {pct(r['hidden_detection'])} | {pct(r['solo_unit_detection'])} "
                     f"| {pct(r['start_detection'])} | {pct(r['spillover_false_alarm'])} | "
                     + " | ".join(pct(r["quiet_hidden"][q]) for q in QUIET) + " |")
        L.append("")
    L += ["## Training cost", "", "| Model | Features | Train time (s) | Trees used | Peak RAM while training (MB) |",
          "|---|---|---|---|---|"]
    for m, t in train_info.items():
        L.append(f"| {m} | {t['n_features']} | {t['train_time_s']:.0f} | {t['best_iteration']} | {t['train_peak_ram_mb']:,.0f} |")
    L += ["", "## Notes", "",
          "- TEST_ORIGINAL is the old test stream: a fair test for every model.",
          "- TEST_SOLO uses the same test flows arranged with many solo attacks. The new models were trained on this "
          "kind of arrangement and the old ones were not, so it shows how much the new training helps on hidden attacks.",
          "- Labels were used only to build the streams. Every model gets the same kind of input in real time.",
          "- Missed attacks = attack flows predicted Benign. False alarms = Benign flows predicted as any attack.",
          "- Hidden-attack groups per class are small in TEST_ORIGINAL, so those percentages are rough."]
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--solo-share", type=float, default=0.10, help="share of each solo-type class put in as solo units")
    ap.add_argument("--other-share", type=float, default=0.03, help="share of every other attack class put in as solo units")
    ap.add_argument("--solo-gap", type=int, default=32, help="normal flows at least before each unit")
    ap.add_argument("--test-solo-share", type=float, default=0.08, help="solo share of every class in TEST_SOLO")
    ap.add_argument("--no-deviation", action="store_true", help="skip the SW_SOLO_DEV model")
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=-1)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    args = ap.parse_args()
    args.gpu_id, args.gpu_platform = 0, 0

    meta = load_meta()
    feats = meta["features"]
    window = meta["window"]
    device = _pick_device("xgboost", args)

    print("1) building the new streams (labels used only to arrange flows) ...")
    streams = {}
    for i, split in enumerate(("train", "val")):
        rng = np.random.default_rng(C.SEED + 100 + i)
        streams[split] = build_mixed_stream(class_parts(split), rng, args.solo_share, args.other_share, args.solo_gap)
        k = streams[split]["unit_kind"].to_numpy()
        print(f"   {split}: {len(k):,} flows, {int((k == 2).sum()):,} solo attack flows, {int((k == 1).sum()):,} burst attack flows")
    test_parts = class_parts("test")
    test_solo = build_mixed_stream(test_parts, np.random.default_rng(C.SEED + 200),
                                   args.test_solo_share, args.test_solo_share, args.solo_gap)
    test_orig = load_split("test")

    print("2) training the new models ...")
    jobs = [("SW_SOLO", "sw")] + ([] if args.no_deviation else [("SW_SOLO_DEV", "sw_dev")])
    train_info = {name: train_new(name, kind, streams, feats, window, args, device) for name, kind in jobs}
    del streams

    print("3) scoring every model on both test sets (CPU) ...")
    models = {"FLAT": (*load_model(HERE.parent / "MODEL XGBOOST" / "output")[:2], "flat"),
              "SW_OLD": (*load_model(HERE / "output")[:2], "sw")}
    for name, kind in jobs:
        models[name] = (*load_model(OUT / name)[:2], kind)
    tests = {"TEST_ORIGINAL": score(models, test_orig, feats, window),
             "TEST_SOLO": score(models, test_solo, feats, window)}

    text = report(tests, train_info, args)
    C.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (C.RESULTS_DIR / "SOLO_TRAINING.md").write_text(text, encoding="utf-8")
    (C.RESULTS_DIR / "solo_training.json").write_text(json.dumps(
        {"settings": vars(args), "solo_type_classes": SOLO_TYPE, "train": train_info, "tests": tests},
        indent=2, default=str), encoding="utf-8")
    print("\n" + text)
    print(f"saved: {C.RESULTS_DIR / 'SOLO_TRAINING.md'}")


if __name__ == "__main__":
    main()
