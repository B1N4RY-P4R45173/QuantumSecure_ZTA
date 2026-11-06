"""
Load CIC-IDS2017 labelled flow CSVs ("GeneratedLabelledFlows" / "TrafficLabelling" version,
the one WITH IPs, ports and timestamps — needed to match Suricata alerts).

Known problems in these files, and what we do:
  * column names start with a space            -> strip
  * some text is not UTF-8 ("Web Attack \x96 ...") -> read as latin-1, clean the label
  * "Fwd Header Length" appears twice          -> drop the copy
  * inf / NaN values                           -> 0
  * empty rows at the end of some files        -> drop
  * time has minutes only and NO AM/PM (1:05 means 13:05)
        -> the capture ran in working hours (about 08:00-17:00), so an hour < 8 means PM
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

import config as K


def _clean_label(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip()
    return s.map(lambda v: re.sub(r"^Web Attack\W+", "Web Attack ", v))


def time_of_day_seconds(ts: pd.Series) -> np.ndarray:
    """'5/7/2017 1:05' -> seconds since midnight, with the AM/PM fix."""
    t = pd.to_datetime(ts.astype(str).str.strip(), dayfirst=True, format="mixed", errors="coerce")
    sec = (t.dt.hour * 3600 + t.dt.minute * 60 + t.dt.second).to_numpy(np.float64)
    sec = np.where(t.dt.hour.to_numpy() < 8, sec + 12 * 3600, sec)
    return sec


def load_flows(csv_paths: list[str]) -> pd.DataFrame:
    parts = []
    for p in csv_paths:
        df = pd.read_csv(p, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = df.loc[:, ~df.columns.duplicated()]
        df = df.drop(columns=[c for c in ("Fwd Header Length.1",) if c in df.columns])
        df = df.dropna(subset=["Label", "Source IP"])
        df["source_csv"] = Path(p).name
        parts.append(df)
        print(f"   {Path(p).name}: {len(df):,} flows")
    df = pd.concat(parts, ignore_index=True)

    df["Label"] = _clean_label(df["Label"])
    df["is_attack"] = (df["Label"] != "BENIGN").astype(np.int8)
    df["tod"] = time_of_day_seconds(df["Timestamp"])
    df = df.dropna(subset=["tod"])

    feats = [c for c in K.CIC_TO_TRUST_COLUMNS if c in df.columns]
    X = df[feats].apply(pd.to_numeric, errors="coerce").to_numpy(np.float64, copy=True)
    X[~np.isfinite(X)] = 0.0
    df[feats] = np.clip(X, -1e12, 1e12).astype(np.float32)
    for c in ("Source Port", "Destination Port", "Protocol"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(-1).astype(np.int64)

    # time order (CSV row order is close to time order; tod makes it exact to the minute)
    df = df.sort_values(["tod"], kind="stable").reset_index(drop=True)
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in K.CIC_TO_TRUST_COLUMNS if c in df.columns]


def to_trust_names(df: pd.DataFrame) -> pd.DataFrame:
    """Feature columns renamed to TRUST Lab names, so the same window code works for both datasets."""
    cols = {c: t for c, t in K.CIC_TO_TRUST_COLUMNS.items() if c in df.columns}
    return df[list(cols)].rename(columns=cols).astype(np.float32)


def split_time_blocks(df: pd.DataFrame) -> np.ndarray:
    """train/test by time block (see BLOCK_MINUTES / BLOCK_PATTERN in config.py)."""
    block = (df["tod"].to_numpy() // (K.BLOCK_MINUTES * 60)).astype(np.int64)
    return np.array(K.BLOCK_PATTERN, dtype=object)[block % len(K.BLOCK_PATTERN)]


def split_train_test(df: pd.DataFrame) -> np.ndarray:
    """Stratified random split by label. Labels with < 2 flows go to train only."""
    from sklearn.model_selection import train_test_split

    rng_idx = np.arange(len(df))
    counts = df["Label"].value_counts()
    rare = df["Label"].isin(counts[counts < 2].index).to_numpy()
    _, test_idx = train_test_split(rng_idx[~rare], test_size=K.TEST_SHARE,
                                   stratify=df["Label"].to_numpy()[~rare], random_state=K.SEED)
    split = np.full(len(df), "train", dtype=object)
    split[test_idx] = "test"
    return split
