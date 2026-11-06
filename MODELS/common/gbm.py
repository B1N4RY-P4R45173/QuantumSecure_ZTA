"""
Shared trainer for the gradient-boosting models.

    algo     = "xgboost" | "lightgbm"
    windowed = False -> one flow = one input           (MODEL XGBOOST, MODEL LIGHTGBM)
               True  -> flow + last-WINDOW statistics  (MODEL SW_XGBOOST, MODEL SW_LIGHTGBM)

The four model folders only call `run(...)` with different settings, so the four
models are trained in exactly the same way and the comparison is fair.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from common import config as C
from common.bench import PeakMemory, latency_ms, timed
from common.data import load_meta, load_split
from common.metrics import evaluate, save_result, text_report
from common.windows import flow_only_features, sliding_window_features, targets


def _class_weights(y: np.ndarray) -> np.ndarray:
    """sqrt-balanced weights: rare attack classes count more, but not extremely more."""
    classes, counts = np.unique(y, return_counts=True)
    w = {c: (len(y) / (len(classes) * n)) ** 0.5 for c, n in zip(classes, counts)}
    return np.array([w[v] for v in y], np.float32)


def _gpu_works(algo: str, args) -> bool:
    """Train a tiny model on the GPU; True if it works on this PC."""
    X = np.random.rand(500, 5).astype(np.float32)
    y = np.arange(500) % 2
    try:
        if algo == "xgboost":
            from xgboost import XGBClassifier
            XGBClassifier(n_estimators=2, device="cuda", tree_method="hist").fit(X, y)
        else:
            from lightgbm import LGBMClassifier
            LGBMClassifier(n_estimators=2, device_type="gpu", gpu_platform_id=args.gpu_platform,
                           gpu_device_id=args.gpu_id, verbose=-1).fit(X, y)
        return True
    except Exception as e:                       # no GPU, no driver, or no GPU build
        print(f"   GPU not usable for {algo}: {str(e).splitlines()[0][:120]}")
        return False


def _pick_device(algo: str, args) -> str:
    """'auto' -> GPU if it works, else CPU. Returns 'gpu' or 'cpu'."""
    if args.device == "cpu":
        return "cpu"
    ok = _gpu_works(algo, args)
    if not ok and args.device in ("cuda", "gpu"):
        print("   -> falling back to CPU")
    return "gpu" if ok else "cpu"


def _make_model(algo: str, n_classes: int, args, device: str):
    if algo == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=args.trees, max_depth=8, learning_rate=args.lr,
            subsample=0.8, colsample_bytree=0.8, tree_method="hist",
            device="cuda" if device == "gpu" else "cpu",
            objective="multi:softprob", num_class=n_classes, eval_metric="mlogloss",
            early_stopping_rounds=30, n_jobs=args.threads, random_state=C.SEED,
        )
    from lightgbm import LGBMClassifier
    gpu = {"device_type": "gpu", "gpu_platform_id": args.gpu_platform, "gpu_device_id": args.gpu_id} \
        if device == "gpu" else {}
    return LGBMClassifier(
        n_estimators=args.trees, num_leaves=63, learning_rate=args.lr,
        subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
        objective="multiclass", n_jobs=args.threads, random_state=C.SEED, verbose=-1, **gpu,
    )


def run(name: str, algo: str, windowed: bool, out_dir: Path) -> None:
    ap = argparse.ArgumentParser(description=f"train {name}")
    ap.add_argument("--trees", type=int, default=400, help="max boosting rounds (early stopping on val)")
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--window", type=int, default=None, help=f"flows per window (default {C.WINDOW})")
    ap.add_argument("--threads", type=int, default=-1, help="CPU threads (-1 = all)")
    ap.add_argument("--device", choices=["auto", "cpu", "cuda", "gpu"], default="auto",
                    help="where to TRAIN (auto = GPU if it works). Speed tests always run on CPU.")
    ap.add_argument("--gpu-id", type=int, default=0, help="GPU number (LightGBM GPU build only)")
    ap.add_argument("--gpu-platform", type=int, default=0, help="OpenCL platform (LightGBM GPU build only)")
    args = ap.parse_args()

    device = _pick_device(algo, args)
    print(f"[{name}] training device: {device.upper()}  (speed is measured on CPU, like an edge gateway)")
    meta = load_meta()
    if meta["quick"]:
        print(f"[{name}] WARNING: processed data is from --quick mode. Run preprocess.py for real results.")
    window = args.window or meta["window"]
    feats = meta["features"]
    build = sliding_window_features if windowed else flow_only_features
    perf: dict = {}

    with PeakMemory() as mem:
        print(f"[{name}] building inputs (window={window if windowed else 1}) ...")
        data = {}
        for split in ("train", "val", "test"):
            df = load_split(split)
            with timed(perf, f"features_{split}_s"):
                X, names = build(df, feats, window)
            y, burst = targets(df, window)
            data[split] = (X, y, burst)
            print(f"   {split:5s} X={X.shape}")
        del df

        Xtr, ytr, _ = data["train"]
        Xva, yva, _ = data["val"]
        Xte, yte, bte = data["test"]

        # models need labels 0..k-1; map our class ids to that and back
        present = np.unique(ytr)                 # sorted class ids seen in training
        ytr_l = np.searchsorted(present, ytr)
        keep_va = np.isin(yva, present)
        yva_l = np.searchsorted(present, yva[keep_va])

        model = _make_model(algo, len(present), args, device)
        print(f"[{name}] training {algo} on {len(Xtr):,} rows, {Xtr.shape[1]} features ...")
        with timed(perf, "train_time_s"):
            if algo == "xgboost":
                model.fit(Xtr, ytr_l, sample_weight=_class_weights(ytr_l),
                          eval_set=[(Xva[keep_va], yva_l)], verbose=50)
            else:
                import lightgbm as lgb
                model.fit(Xtr, ytr_l, sample_weight=_class_weights(ytr_l),
                          eval_set=[(Xva[keep_va], yva_l)],
                          callbacks=[lgb.early_stopping(30), lgb.log_evaluation(50)])

        # edge gateways have no GPU: always test and time the model on the CPU
        if algo == "xgboost":
            model.set_params(device="cpu")
        print(f"[{name}] testing on CPU ...")
        with timed(perf, "predict_test_s"):
            y_pred = present[model.predict(Xte).astype(int).ravel()]

    # ---- speed: features + prediction, per flow
    n = len(Xte)
    total_s = perf["features_test_s"] + perf["predict_test_s"]
    feat_ms_per_flow = perf["features_test_s"] / n * 1000
    one = [Xte[i:i + 1] for i in range(0, min(n, 3000), 10)]
    lat = latency_ms(model.predict, one) + feat_ms_per_flow

    # ---- save model
    out_dir.mkdir(parents=True, exist_ok=True)
    if algo == "xgboost":
        model_path = out_dir / "model.json"
        model.save_model(model_path)
    else:
        model_path = out_dir / "model.txt"
        model.booster_.save_model(str(model_path))
    (out_dir / "feature_names.json").write_text(json.dumps(names, indent=2), encoding="utf-8")
    # everything predict.py needs to use the saved model again
    info = {
        "name": name, "algo": algo, "windowed": windowed, "window": window,
        "model_file": model_path.name,
        "base_features": feats,                      # columns needed from the input CSV
        "classes": [C.CLASSES[i] for i in present],  # model output index -> class name
    }
    (out_dir / "model_info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")

    res = evaluate(yte, y_pred, bte)
    report = text_report(name, yte, y_pred, res)
    (out_dir / "report.txt").write_text(report, encoding="utf-8")
    print("\n" + report)

    save_result(name, {
        "family": f"{algo} ({'sliding window' if windowed else 'single flow'})",
        "input": f"current flow + statistics of last {window} flows" if windowed else "one flow",
        "window_flows": window if windowed else 1,
        "needs_flow_end": True,          # CICFlowMeter features exist only after the flow ends
        "can_drop_first_packet": False,
        "quick_data": meta["quick"],
        "detection": res,
        "performance": {
            "train_time_s": perf["train_time_s"],
            "train_device": device,
            "speed_measured_on": "cpu",
            "model_size_mb": model_path.stat().st_size / 2**20,
            "test_flows": n,
            "throughput_flows_per_s": n / total_s,
            "equiv_packets_per_s": n / total_s * meta["avg_packets_per_flow_test"],
            "latency_ms_single": lat,
            "peak_ram_mb": mem.peak_mb,
            "n_features": len(names),
            "best_iteration": getattr(model, "best_iteration", None) or getattr(model, "best_iteration_", None),
        },
        "notes": [
            "Throughput excludes CICFlowMeter feature extraction from packets (it is optimistic for ML).",
            "equiv_packets_per_s = flows/s x average packets per flow in the test stream.",
        ],
    })
    print(f"[{name}] done in {time.strftime('%H:%M:%S')}")
