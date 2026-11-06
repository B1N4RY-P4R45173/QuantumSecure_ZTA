"""
Step 1 — Preprocess the TRUST Lab dataset (run this once, before any model).

    python preprocess.py            # full run
    python preprocess.py --quick    # small run (a few minutes) to check that everything works

What it does:
  1. Decompress every class folder to data/extracted/<Class>.csv (only the first time).
  2. Load each class in time order, keep the useful columns, clean inf/NaN.
  3. Split every class by time: first 70% train, next 15% val, last 15% test.
     (Split by time, not randomly: windows overlap, so a random split would leak
      the same flows into train and test.)
  4. Build one mixed time stream per split (attack bursts inside benign traffic).
  5. Save data/processed/{train,val,test}.parquet and meta.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import config as C                     # noqa: E402
from common.data import extract_class, feature_columns, load_class, read_header  # noqa: E402
from common.stream import build_stream             # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small sample, to test the pipeline")
    ap.add_argument("--all", action="store_true", help="use EVERY flow (no sampling limit)")
    ap.add_argument("--max-attack", type=int, default=None, help=f"flows per attack class (default {C.MAX_FLOWS_PER_ATTACK:,})")
    ap.add_argument("--max-benign", type=int, default=None, help=f"benign flows (default {C.MAX_FLOWS_BENIGN:,})")
    args = ap.parse_args()

    if not C.DATASET_DIR.exists():
        raise SystemExit(f"dataset folder not found: {C.DATASET_DIR}\n"
                         f"set TRUSTLAB_DIR to the 'Datasets' folder of TRUST Lab")
    rng = np.random.default_rng(C.SEED)
    if args.all:
        cap_attack = cap_benign = None                   # no limit
    elif args.quick:
        cap_attack, cap_benign = C.QUICK_ATTACK, C.QUICK_BENIGN
    else:
        cap_attack, cap_benign = C.MAX_FLOWS_PER_ATTACK, C.MAX_FLOWS_BENIGN
    if args.max_attack:
        cap_attack = args.max_attack
    if args.max_benign:
        cap_benign = args.max_benign
    print(f"sampling: attack {cap_attack or 'ALL'} per class, benign {cap_benign or 'ALL'}")

    print(f"dataset: {C.DATASET_DIR}")
    print("1) decompressing (only the first time, the biggest file takes a few minutes) ...")
    truncated = []
    for cls in C.CLASSES:
        t0 = time.time()
        path, trunc = extract_class(cls)
        if trunc:
            truncated.append(cls)
        print(f"   {cls:15s} {path.stat().st_size / 2**20:8.1f} MB"
              f"{'  (WARNING: .gz file ends early, partial data kept)' if trunc else ''}"
              f"  [{time.time() - t0:.0f}s]")

    # the same feature list for every class (Benign has 2 extra columns, they are dropped)
    features = feature_columns(read_header(C.EXTRACT_DIR / "DoS.csv"))
    print(f"2) loading classes ({len(features)} features) ...")
    splits = {"train": {}, "val": {}, "test": {}}
    counts = {}
    for cls in C.CLASSES:
        cap = cap_benign if cls == C.BENIGN else cap_attack
        df = load_class(cls, features, cap, rng)
        n = len(df)
        a, b = int(n * C.SPLIT[0]), int(n * (C.SPLIT[0] + C.SPLIT[1]))
        splits["train"][cls], splits["val"][cls], splits["test"][cls] = df[:a], df[a:b], df[b:]
        counts[cls] = {"train": a, "val": b - a, "test": n - b}
        print(f"   {cls:15s} {n:>9,d} flows  (train {a:,} / val {b - a:,} / test {n - b:,})")

    # drop features that never change in the training data (they carry no information)
    train_all = pd.concat(splits["train"].values())
    constant = [f for f in features if train_all[f].nunique() <= 1]
    features = [f for f in features if f not in constant]
    del train_all
    print(f"   removed {len(constant)} constant features: {constant}")

    print("3) building time streams ...")
    C.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    stream_info = {}
    for name, parts in splits.items():
        parts = {c: df[features] for c, df in parts.items()}
        s = build_stream(parts, rng)
        s.to_parquet(C.PROCESSED_DIR / f"{name}.parquet", index=False)
        stream_info[name] = {"flows": len(s), "bursts": int(s["burst"].max() + 1),
                             "attack_share": float((s["burst"] >= 0).mean())}
        print(f"   {name:5s} {len(s):>9,d} flows, {stream_info[name]['bursts']} attack bursts, "
              f"{stream_info[name]['attack_share']:.1%} attack flows")

    test = pd.read_parquet(C.PROCESSED_DIR / "test.parquet", columns=["Tot Fwd Pkts", "Tot Bwd Pkts"])
    meta = {
        "features": features,
        "classes": C.CLASSES,
        "window": C.WINDOW,
        "quick": args.quick,
        "max_flows_per_attack": cap_attack,          # None = all flows
        "max_flows_benign": cap_benign,
        "counts": counts,
        "streams": stream_info,
        "truncated_files": truncated,
        "removed_constant_features": constant,
        # used to turn "flows per second" into "packets per second" for the Suricata comparison
        "avg_packets_per_flow_test": float((test["Tot Fwd Pkts"] + test["Tot Bwd Pkts"]).mean()),
    }
    (C.PROCESSED_DIR / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"done -> {C.PROCESSED_DIR}")


if __name__ == "__main__":
    main()
