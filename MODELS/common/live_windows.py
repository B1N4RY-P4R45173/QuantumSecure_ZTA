"""
Fast LIVE feature builder: one flow in -> one model input out.

The training code (common/windows.py sliding_window_features and train_solo.py
deviation_features) uses pandas over the whole stream. That is fast for 1.5 million
rows at once, but slow for one flow at a time (about 3-8 ms per flow, mostly pandas
overhead). This class keeps the last flows in a small numpy buffer and computes the
SAME numbers for the newest flow only.

    b = LiveFeatureBuilder(features, windows=[8, 56], dev=8)     # BAL_MS
    row = b.push(flow_values)        # None until the longest window is full
    probs = model.predict(row[None, :])

Column order (must match the training code exactly):
    first window : current flow (all base features) + its window statistics
    next windows : window statistics only
    dev          : (current - window mean) / (window std + 1e-6) for WINDOW_STAT_FEATURES
Window statistics = mean, std (ddof=1), min, max of WINDOW_STAT_FEATURES, then the shares
of SYN / RST / TCP / short (< 1 ms) flows, then unique Dst Ports and share of the same Dst Port.
"""

from __future__ import annotations

import numpy as np

from common import config as C


class LiveFeatureBuilder:
    def __init__(self, features: list[str], windows: list[int], dev: int | None = None):
        self.feats = list(features)
        self.windows = list(windows)
        self.dev = dev
        self.stat_idx = np.array([self.feats.index(f) for f in C.WINDOW_STAT_FEATURES if f in self.feats])
        self.i_syn = self.feats.index("SYN Flag Cnt")
        self.i_rst = self.feats.index("RST Flag Cnt")
        self.i_proto = self.feats.index("Protocol")
        self.i_dur = self.feats.index("Flow Duration")
        self.i_port = self.feats.index("Dst Port")
        self.maxw = max(self.windows + [dev or 1, 1])
        self.cap = max(2 * self.maxw, 2)
        k = len(self.stat_idx)
        self.S = np.zeros((self.cap, k))          # window-statistic features (float64, like pandas rolling)
        self.I = np.zeros((self.cap, 4))          # SYN>0, RST>0, TCP, duration < 1 ms
        self.P = np.zeros(self.cap)               # Dst Port
        self.pos = 0
        self.seen = 0

    @property
    def n_features(self) -> int:
        n = len(self.feats) + len(self.windows) * (4 * len(self.stat_idx) + 6)
        return n + (len(self.stat_idx) if self.dev else 0)

    def _append(self, x: np.ndarray) -> None:
        if self.pos == self.cap:                   # keep the newest maxw-1 rows, start again
            keep = self.maxw - 1
            if keep:
                self.S[:keep] = self.S[self.pos - keep:self.pos]
                self.I[:keep] = self.I[self.pos - keep:self.pos]
                self.P[:keep] = self.P[self.pos - keep:self.pos]
            self.pos = keep
        p = self.pos
        self.S[p] = x[self.stat_idx]
        self.I[p, 0] = x[self.i_syn] > 0
        self.I[p, 1] = x[self.i_rst] > 0
        self.I[p, 2] = x[self.i_proto] == 6
        self.I[p, 3] = x[self.i_dur] < 1_000
        self.P[p] = x[self.i_port]
        self.pos += 1
        self.seen += 1

    def push(self, flow: np.ndarray) -> np.ndarray | None:
        """Add the newest flow (base features, training order). Returns its model input,
        or None while the longest window is not full yet."""
        x = np.asarray(flow, np.float32)
        self._append(x)
        if not self.windows:                       # plain model: the flow itself
            return x
        if self.seen < self.maxw:
            return None
        parts = []
        cache = {}
        for j, w in enumerate(self.windows):
            S = self.S[self.pos - w:self.pos]
            mean, std = S.mean(0), S.std(0, ddof=1)
            cache[w] = (mean, std)
            P = self.P[self.pos - w:self.pos]
            stats = np.concatenate([mean, std, S.min(0), S.max(0), self.I[self.pos - w:self.pos].mean(0),
                                    [np.unique(P).size, (P == P[-1]).mean()]]).astype(np.float32)
            parts.append(np.concatenate([x, stats]) if j == 0 else stats)
        out = np.concatenate(parts)
        out[~np.isfinite(out)] = 0.0
        if self.dev:
            if self.dev in cache:
                mean, std = cache[self.dev]
            else:
                S = self.S[self.pos - self.dev:self.pos]
                mean, std = S.mean(0), S.std(0, ddof=1)
            z = ((self.S[self.pos - 1] - mean) / (std + 1e-6)).astype(np.float32)
            z[~np.isfinite(z)] = 0.0
            out = np.concatenate([out, z])
        return out
