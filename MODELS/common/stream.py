"""
Build one realistic *time stream* of flows.

Problem: in TRUST Lab every class was recorded in a separate session, so each
file holds only one class. Real traffic is mixed: attacks happen *inside*
normal traffic.

Solution: cut each attack class into bursts (BURST_MIN..BURST_MAX flows). Then
build the stream like this:

    [benign gap] [burst: attack + some benign mixed] [benign gap] [burst] ...

  * Inside a burst, attack flows keep their original time order.
  * Benign flows are also used in their original time order.
  * Every attack flow gets a `burst` id, so we can later measure
    "how many attack flows passed before the first alert" (time to detect).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from common import config as C


def build_stream(parts: dict[str, pd.DataFrame], rng: np.random.Generator) -> pd.DataFrame:
    """`parts` maps class name -> time-ordered DataFrame (same columns for all)."""
    benign = parts[C.BENIGN]
    attacks = {c: df for c, df in parts.items() if c != C.BENIGN and len(df) > 0}

    # 1) cut every attack class into bursts
    bursts = []                                   # (class, start, end)
    for cls, df in attacks.items():
        pos, n = 0, len(df)
        while pos < n:
            L = min(int(rng.integers(C.BURST_MIN, C.BURST_MAX + 1)), n - pos)
            bursts.append((cls, pos, pos + L))
            pos += L
    order = rng.permutation(len(bursts))
    bursts = [bursts[i] for i in order]

    # 2) how many benign flows go inside each burst, and how many into the gaps
    nb = len(benign)
    share = rng.uniform(C.ATTACK_SHARE_MIN, C.ATTACK_SHARE_MAX, size=len(bursts))
    inside = np.array([(e - s) * (1 - p) / p for (_, s, e), p in zip(bursts, share)])
    budget = nb * (1 - C.BACKGROUND_SHARE)
    if inside.sum() > budget:
        inside *= budget / inside.sum()
    inside = inside.astype(np.int64)
    remaining = nb - int(inside.sum())
    cuts = np.sort(rng.integers(0, remaining + 1, size=len(bursts)))
    gaps = np.diff(np.concatenate([[0], cuts, [remaining]]))   # len(bursts) + 1 gaps

    # 3) global row index into one big matrix: [benign rows, then each attack class]
    offsets, mats, labels_of = {}, [], []
    off = 0
    for cls, df in [(C.BENIGN, benign), *attacks.items()]:
        offsets[cls] = off
        mats.append(df.to_numpy(dtype=np.float32))
        off += len(df)
    big = np.concatenate(mats)

    idx_parts, lab_parts, burst_parts = [], [], []
    bp = 0                                        # next benign row to use

    def add_benign(k: int):
        nonlocal bp
        k = min(k, nb - bp)
        idx_parts.append(np.arange(bp, bp + k))
        lab_parts.append(np.full(k, C.CLASS_TO_ID[C.BENIGN], np.int8))
        burst_parts.append(np.full(k, -1, np.int32))
        bp += k

    for b, ((cls, s, e), m, g) in enumerate(zip(bursts, inside, gaps[:-1])):
        add_benign(int(g))
        L = e - s
        m = int(min(m, nb - bp))
        is_attack = np.zeros(L + m, bool)
        is_attack[rng.choice(L + m, size=L, replace=False)] = True
        idx = np.empty(L + m, np.int64)
        idx[is_attack] = offsets[cls] + np.arange(s, e)
        idx[~is_attack] = np.arange(bp, bp + m)
        bp += m
        lab = np.where(is_attack, C.CLASS_TO_ID[cls], C.CLASS_TO_ID[C.BENIGN]).astype(np.int8)
        bur = np.where(is_attack, b, -1).astype(np.int32)
        idx_parts.append(idx); lab_parts.append(lab); burst_parts.append(bur)
    add_benign(nb - bp)                            # last gap: all benign rows left

    idx = np.concatenate(idx_parts)
    out = pd.DataFrame(big[idx], columns=benign.columns)
    out["label"] = np.concatenate(lab_parts)
    out["burst"] = np.concatenate(burst_parts)
    return out
