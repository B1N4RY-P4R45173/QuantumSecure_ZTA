"""
Turning the flow stream into model inputs.

Every model is scored on the same rows: positions WINDOW-1 .. end of the stream
(the first WINDOW-1 flows have no full window, so nobody is scored on them).

  * flow_only_features  -> one flow = one input            (XGBoost, LightGBM)
  * sliding_window_features -> current flow + statistics of the last WINDOW flows
                                                           (SW-XGBoost, SW-LightGBM)
  * LSTM                -> the last WINDOW flows as a sequence (built in MODEL LSTM/train.py,
                           using the Scaler below)
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view

from common import config as C


def valid_slice(n: int, window: int) -> slice:
    return slice(window - 1, n)


def flow_only_features(df: pd.DataFrame, features: list[str], window: int):
    X = df[features].to_numpy(np.float32)[valid_slice(len(df), window)]
    return X, list(features)


def _window_unique_and_same(values: np.ndarray, window: int, chunk: int = 200_000):
    """Per window: number of unique values, and share equal to the current (last) value."""
    v = sliding_window_view(values, window)          # (n-window+1, window), no copy
    uniq = np.empty(len(v), np.float32)
    same = np.empty(len(v), np.float32)
    for i in range(0, len(v), chunk):
        w = v[i:i + chunk]
        s = np.sort(w, axis=1)
        uniq[i:i + chunk] = 1 + (np.diff(s, axis=1) != 0).sum(axis=1)
        same[i:i + chunk] = (w == w[:, -1:]).mean(axis=1)
    return uniq, same


def sliding_window_features(df: pd.DataFrame, features: list[str], window: int):
    """Current flow features + statistics over the last `window` flows."""
    sl = valid_slice(len(df), window)
    cols, names = [df[features].to_numpy(np.float32)[sl]], list(features)

    stat_feats = [f for f in C.WINDOW_STAT_FEATURES if f in df.columns]
    r = df[stat_feats].rolling(window, min_periods=window)
    for stat in ("mean", "std", "min", "max"):
        cols.append(getattr(r, stat)().to_numpy(np.float32)[sl])
        names += [f"w_{stat}_{f}" for f in stat_feats]

    # behaviour of the whole window (useful for scans and floods)
    extra = {
        "w_share_syn": (df["SYN Flag Cnt"] > 0).astype(np.float32),
        "w_share_rst": (df["RST Flag Cnt"] > 0).astype(np.float32),
        "w_share_tcp": (df["Protocol"] == 6).astype(np.float32),
        "w_share_short": (df["Flow Duration"] < 1_000).astype(np.float32),   # < 1 ms
    }
    for name, s in extra.items():
        cols.append(s.rolling(window, min_periods=window).mean().to_numpy(np.float32)[sl][:, None])
        names.append(name)

    uniq, same = _window_unique_and_same(df["Dst Port"].to_numpy(np.float64), window)
    cols += [uniq[:, None], same[:, None]]
    names += ["w_unique_dst_ports", "w_share_same_dst_port"]

    X = np.hstack(cols)
    X[~np.isfinite(X)] = 0.0
    return X, names


def targets(df: pd.DataFrame, window: int):
    sl = valid_slice(len(df), window)
    return df["label"].to_numpy(np.int64)[sl], df["burst"].to_numpy(np.int64)[sl]


# ---------------------------------------------------------------- LSTM helpers
def signed_log(x: np.ndarray) -> np.ndarray:
    """log1p that also works for negative values. Shrinks huge values (bytes/s)."""
    return np.sign(x) * np.log1p(np.abs(x))


class Scaler:
    """signed_log + standardisation, fitted on the training stream only."""

    def fit(self, X: np.ndarray) -> "Scaler":
        Z = signed_log(X)
        self.mean = Z.mean(0)
        self.std = Z.std(0) + 1e-6
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        return ((signed_log(X) - self.mean) / self.std).astype(np.float32)

    def state(self) -> dict:
        return {"mean": self.mean.tolist(), "std": self.std.tolist()}
