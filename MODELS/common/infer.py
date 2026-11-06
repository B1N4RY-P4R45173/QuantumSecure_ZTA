"""
Shared code for predict.py (using a saved model).

Input can be:
  * --split test            the processed test stream (to check the saved model)
  * --csv new_flows.csv     a CICFlowMeter CSV (same column names as TRUST Lab).
                            If it has a "Label" column, metrics are printed too.

Output: a CSV with one row per flow: predicted class and confidence.
For window models (SW_*, LSTM) the first WINDOW-1 flows have no prediction,
because there is not enough history yet.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from common import config as C
from common.data import column_renames, load_split
from common.metrics import evaluate, text_report

INFO_COLS = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]


def parse_args(name: str) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=f"run the saved {name} model")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--split", choices=["train", "val", "test"], default="test",
                     help="processed stream to predict on (default: test)")
    src.add_argument("--csv", help="CICFlowMeter CSV file with new flows")
    ap.add_argument("--out", help="output CSV (default: output/predictions_<input>.csv)")
    return ap.parse_args()


def load_input(args, base_features: list[str]):
    """Return (features DataFrame, info DataFrame, y_true or None, source name)."""
    if args.csv:
        df = pd.read_csv(args.csv, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = df.rename(columns=column_renames(df.columns))
        missing = [f for f in base_features if f not in df.columns]
        if missing:
            raise SystemExit(f"CSV is missing {len(missing)} feature columns, e.g. {missing[:5]}")
        if C.TIME_COL in df.columns:                       # windows need time order
            t = pd.to_numeric(df[C.TIME_COL], errors="coerce")
            df = df.iloc[np.argsort(t.to_numpy(), kind="stable")].reset_index(drop=True)
        X = df[base_features].apply(pd.to_numeric, errors="coerce").to_numpy(np.float64)
        X[~np.isfinite(X)] = 0.0
        feats = pd.DataFrame(np.clip(X, -1e12, 1e12).astype(np.float32), columns=base_features)
        info = df[[c for c in INFO_COLS if c in df.columns]].copy()
        y = None
        if "Label" in df.columns:
            cls = df["Label"].astype(str).str.strip().str.lower().map(C.LABEL_ALIASES)
            y = cls.map(C.CLASS_TO_ID).fillna(-1).astype(int).to_numpy()   # -1 = unknown label
        return feats, info, y, Path(args.csv).stem

    df = load_split(args.split)
    info = pd.DataFrame({"position": np.arange(len(df)), "burst": df["burst"].to_numpy()})
    return df[base_features], info, df["label"].to_numpy(np.int64), args.split


def write_output(out_dir: Path, args, source: str, info: pd.DataFrame, valid_from: int,
                 classes: list[str], prob: np.ndarray, y_true: np.ndarray | None, name: str) -> None:
    """`prob` has one row per flow from `valid_from` to the end."""
    n = len(info)
    pred_local = prob.argmax(1)
    pred_name = np.full(n, "", dtype=object)
    conf = np.full(n, np.nan)
    pred_name[valid_from:] = np.array(classes, dtype=object)[pred_local]
    conf[valid_from:] = prob.max(1)

    out = info.copy()
    out["predicted_class"] = pred_name
    out["confidence"] = np.round(conf, 4)
    out["is_attack"] = np.where(pred_name == "", "", np.where(pred_name == C.BENIGN, "no", "yes"))
    if y_true is not None:
        out["true_class"] = [C.CLASSES[v] if v >= 0 else "?" for v in y_true]

    path = Path(args.out) if args.out else out_dir / f"predictions_{source}.csv"
    out.to_csv(path, index=False)
    print(f"saved: {path}  ({n:,} flows, {n - valid_from:,} with a prediction)")
    counts = pd.Series(pred_name[valid_from:]).value_counts()
    print("predicted classes:\n" + counts.to_string())

    if y_true is not None:
        yt = y_true[valid_from:]
        yp = np.array([C.CLASS_TO_ID[c] for c in pred_name[valid_from:]])
        known = yt >= 0
        burst = info["burst"].to_numpy()[valid_from:][known] if "burst" in info else None
        res = evaluate(yt[known], yp[known], burst)
        print("\n" + text_report(name, yt[known], yp[known], res))
