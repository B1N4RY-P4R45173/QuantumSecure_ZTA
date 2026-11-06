"""
Shared predict code for the 4 gradient-boosting models.
Loads output/model.json (XGBoost) or output/model.txt (LightGBM) + output/model_info.json.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from common.infer import load_input, parse_args, write_output
from common.windows import sliding_window_features


def run_predict(name: str, out_dir: Path) -> None:
    args = parse_args(name)
    info_path = out_dir / "model_info.json"
    if not info_path.exists():
        raise SystemExit(f"no saved model in {out_dir} — run train.py first")
    info = json.loads(info_path.read_text(encoding="utf-8"))
    model_file = out_dir / info["model_file"]

    if info["algo"] == "xgboost":
        import xgboost as xgb
        booster = xgb.Booster()
        booster.load_model(str(model_file))
        predict_proba = lambda X: booster.predict(xgb.DMatrix(X))            # noqa: E731
    else:
        import lightgbm as lgb
        booster = lgb.Booster(model_file=str(model_file))
        predict_proba = booster.predict

    feats, meta, y_true, source = load_input(args, info["base_features"])
    t0 = time.perf_counter()
    if info["windowed"]:
        if len(feats) < info["window"]:
            raise SystemExit(f"need at least {info['window']} flows for a window model")
        X, _ = sliding_window_features(feats, info["base_features"], info["window"])
        valid_from = info["window"] - 1
    else:
        X, valid_from = feats.to_numpy(np.float32), 0
    prob = np.asarray(predict_proba(X)).reshape(len(X), -1)
    print(f"[{name}] predicted {len(X):,} flows in {time.perf_counter() - t0:.2f}s")

    write_output(out_dir, args, source, meta, valid_from, info["classes"], prob, y_true, name)
