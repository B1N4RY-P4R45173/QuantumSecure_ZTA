"""
Step 2 — XGBoost and SW-XGBoost on the same CIC-IDS2017 day (Windows or Linux).

    python step2_xgboost.py --day Wednesday --csv data/csv/Wednesday-workingHours.pcap_ISCX.csv

Four ML detectors, all scored on the SAME test flows (time-block split):
  XGB_RETRAINED      one flow,          trained on CIC-IDS2017 train blocks
  SW_XGB_RETRAINED   flow + last 32,    trained on CIC-IDS2017 train blocks
  XGB_TRUSTLAB       one flow,          model from "MODEL XGBOOST"    (never saw CIC-IDS2017)
  SW_XGB_TRUSTLAB    flow + last 32,    model from "MODEL SW_XGBOOST" (never saw CIC-IDS2017)

Window features are built over the whole day in time order (like a live detector, which sees
all traffic). The first WINDOW-1 flows have no full window and are not scored.
Training can use the NVIDIA GPU (--device cuda); speed is always measured on the CPU.

Saves output/<day>/: flows.parquet, xgb_predictions.parquet, xgb_perf.json, *_retrained.json models
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import numpy as np
import pandas as pd

import config as K
from cicids import load_flows, split_time_blocks, split_train_test, to_trust_names

sys.path.insert(0, str(K.MODELS))
from common.bench import PeakMemory, latency_ms, timed                      # noqa: E402
from common.windows import flow_only_features, sliding_window_features      # noqa: E402

BUILDERS = {False: flow_only_features, True: sliding_window_features}


def gpu_ok() -> bool:
    from xgboost import XGBClassifier
    try:
        XGBClassifier(n_estimators=2, device="cuda", tree_method="hist").fit(
            np.random.rand(200, 4), np.arange(200) % 2)
        return True
    except Exception:
        return False


def build(trust: pd.DataFrame, feats: list[str], windowed: bool, perf: dict) -> np.ndarray:
    """Model input for every flow from position WINDOW-1 on (same rows for all detectors)."""
    with timed(perf, "features_all_s"):
        X, _ = BUILDERS[windowed](trust, feats, K.WINDOW)
    return X


def retrained(name: str, X: np.ndarray, labels: np.ndarray, tr: np.ndarray, te: np.ndarray,
              device: str, out_dir, perf: dict) -> np.ndarray:
    from xgboost import XGBClassifier

    classes = np.unique(labels[tr])                       # labels seen in training
    y = np.searchsorted(classes, labels[tr])
    counts = np.bincount(y, minlength=len(classes))
    w = (len(y) / (len(classes) * counts)) ** 0.5           # sqrt-balanced, like MODELS/
    model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8,
                          colsample_bytree=0.8, tree_method="hist", device=device,
                          n_jobs=-1, random_state=K.SEED)
    print(f"   [{name}] training on {tr.sum():,} flows, {X.shape[1]} features, device={device} ...")
    with timed(perf, "train_time_s"):
        model.fit(X[tr], y, sample_weight=w[y])
    model.set_params(device="cpu")                          # edge gateways have no GPU
    Xte = X[te]
    with timed(perf, "predict_s"):
        pred = classes[model.predict(Xte).astype(int)]
    perf["latency_ms_single"] = latency_ms(model.predict, [Xte[i:i + 1] for i in range(0, min(len(Xte), 3000), 10)])
    perf["train_device"] = device
    model.save_model(str(out_dir / f"{name.lower()}.json"))
    return pred


def trustlab(name: str, model_dir, trust: pd.DataFrame, te: np.ndarray, perf: dict):
    import xgboost as xgb

    info_path = model_dir / "model_info.json"
    if not info_path.exists():
        print(f"   [{name}] skipped: no trained model in {model_dir} (train it in MODELS first)")
        return None
    info = json.loads(info_path.read_text(encoding="utf-8"))
    missing = [f for f in info["base_features"] if f not in trust.columns]
    if missing:
        print(f"   [{name}] WARNING: {len(missing)} features missing in CIC-IDS2017, set to 0: {missing}")
        trust = trust.assign(**{f: np.float32(0) for f in missing})
    X = build(trust, info["base_features"], info["windowed"], perf)
    booster = xgb.Booster()
    booster.load_model(str(model_dir / info["model_file"]))
    booster.set_param({"device": "cpu"})
    Xte = X[te]
    with timed(perf, "predict_s"):
        prob = booster.predict(xgb.DMatrix(Xte))
    perf["missing_features"] = missing
    perf["train_device"] = "TRUST Lab model"
    return np.array(info["classes"])[prob.reshape(len(Xte), -1).argmax(1)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--csv", nargs="+", required=True, help="one or more CIC-IDS2017 CSVs of this day")
    ap.add_argument("--split", choices=["blocks", "random"], default="blocks",
                    help="blocks = time blocks (default, no window leakage); random = old random split")
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto", help="where to TRAIN")
    args = ap.parse_args()
    out = K.OUT / args.day
    out.mkdir(parents=True, exist_ok=True)

    print("1) loading CIC-IDS2017 flows ...")
    df = load_flows(args.csv)                                   # sorted by time
    df["split"] = split_time_blocks(df) if args.split == "blocks" else split_train_test(df)
    df.loc[df.index[:K.WINDOW - 1], "split"] = "skip"          # no full window yet
    trust = to_trust_names(df)
    base = list(trust.columns)

    keep = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol",
            "Timestamp", "tod", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Label", "is_attack", "split"]
    df[keep].to_parquet(out / "flows.parquet")

    v = df.index[K.WINDOW - 1:]                                 # rows that have model input
    split_v = df.loc[v, "split"].to_numpy()
    tr, te = split_v == "train", split_v == "test"
    labels = df.loc[v, "Label"].to_numpy()
    test_index = v[te]
    print(f"   {len(df):,} flows | split={args.split} | train {tr.sum():,} | test {te.sum():,} "
          f"({int(df.loc[test_index, 'is_attack'].sum()):,} attack)")
    print("   test labels:\n" + df.loc[test_index, "Label"].value_counts().to_string())
    unseen = sorted(set(labels[te]) - set(labels[tr]))
    if unseen:
        print(f"   NOTE: labels only in test (retrained models never saw them): {unseen}")

    device = "cpu"
    if args.device in ("auto", "cuda"):
        device = "cuda" if gpu_ok() else "cpu"
        if device == "cpu":
            print("   GPU not usable -> training on CPU")

    preds = pd.DataFrame(index=test_index)
    all_perf = {}
    n_all = len(v)
    jobs = [
        ("XGB_RETRAINED", "xgb_retrained", False, None),
        ("SW_XGB_RETRAINED", "sw_xgb_retrained", True, None),
        ("XGB_TRUSTLAB", "xgb_trustlab", False, K.TRUST_XGB_DIR),
        ("SW_XGB_TRUSTLAB", "sw_xgb_trustlab", True, K.SW_XGB_DIR),
    ]
    for i, (name, col, windowed, model_dir) in enumerate(jobs, start=2):
        print(f"{i}) {name} ...")
        perf = {"window_flows": K.WINDOW if windowed else 1}
        with PeakMemory() as mem:
            if model_dir is None:
                X = build(trust, base, windowed, perf)
                p = retrained(name, X, labels, tr, te, device, out, perf)
            else:
                p = trustlab(name, model_dir, trust, te, perf)
        if p is None:
            continue
        preds[col] = p
        # per-flow cost = share of the feature building + prediction, measured on CPU
        feat_s = perf["features_all_s"] * te.sum() / n_all
        perf["throughput_flows_per_s"] = te.sum() / (perf["predict_s"] + feat_s)
        perf["peak_ram_mb"] = mem.peak_mb
        all_perf[name] = perf
        print(f"   [{name}] {perf['throughput_flows_per_s']:,.0f} flows/s on CPU")

    preds.to_parquet(out / "xgb_predictions.parquet")
    (out / "xgb_perf.json").write_text(json.dumps(all_perf, indent=2), encoding="utf-8")
    print(f"saved: {out}  [{time.strftime('%H:%M:%S')}]")


if __name__ == "__main__":
    main()
