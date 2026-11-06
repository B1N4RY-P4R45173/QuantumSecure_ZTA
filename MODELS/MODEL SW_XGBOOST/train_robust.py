"""
SW-XGBoost (window 32) trained on TRUST Lab WITHOUT the 6 "bulk" features.

    python "MODEL SW_XGBOOST/train_robust.py"

Why: TRUST Lab's flow tool is not public. Its 6 bulk features follow its own rule
(one number K per flow: Fwd Pkts/b Avg = fwd bytes / K, Fwd Blk Rate Avg = fwd packets / K,
Fwd Byts/b Avg = Bwd Byts/b Avg = K / duration, same for Bwd), and K cannot be computed from
any public flow tool. The normal SW-XGBoost gets 18.9% of its total gain from these 6 features
(Bwd Byts/b Avg is its top feature), so it breaks on flows from another tool, including a live
gateway's. This model learns without them, so it can be tested on CIC-IDS2017 fairly and run
on a gateway.

Same settings as window_sweep.py (window 32, same trees, class weights, early stopping on val).
Saves MODEL SW_XGBOOST/robust/w32/ (model.json, model_info.json, result.json).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import window_sweep                                  # noqa: E402
from common.data import load_meta, load_split       # noqa: E402
from common.gbm import _pick_device                  # noqa: E402

BULK = ["Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
        "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=32)
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=-1)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    args = ap.parse_args()
    args.gpu_id, args.gpu_platform = 0, 0

    feats = [f for f in load_meta()["features"] if f not in BULK]
    print(f"{len(feats)} base features (removed: {BULK})")
    window_sweep.OUT = HERE / "robust"               # do not overwrite window_sweep/w32
    device = _pick_device("xgboost", args)
    splits = {name: load_split(name) for name in ("train", "val", "test")}
    r = window_sweep.train_one((args.window,), args.window - 1, splits, feats, args, device)
    b = r["test"]["binary"]
    print(f"TRUST Lab test: F1 {b['f1']:.4f} | detection {window_sweep.pct(b['recall_detection_rate'])} | "
          f"false alarms {window_sweep.pct(b['false_positive_rate'])} ({b['fp']:,}) | "
          f"missed {b['fn']:,} | macro F1 {r['test']['macro_f1']:.4f}")
    print(f"saved: {window_sweep.OUT / ('w' + str(args.window))}")


if __name__ == "__main__":
    main()
