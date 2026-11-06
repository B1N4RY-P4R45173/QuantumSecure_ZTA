"""
Loading the TRUST Lab CSV files.

Steps for each class (folder):
  1. Join the split parts (.gz.001, .gz.002, ...) and decompress them to one .csv
     (done once, saved in data/extracted/).
  2. Read only the useful columns, as float32.
  3. Sort the flows by Timestamp (time order matters for windows and LSTM).
  4. If the class is too big, keep several *contiguous* blocks, so short
     time sequences stay complete.
"""

from __future__ import annotations

import glob
import zlib
from pathlib import Path

import numpy as np
import pandas as pd

from common import config as C


def _iter_bytes(paths: list[str], chunk: int = 1 << 20):
    for p in paths:
        with open(p, "rb") as f:
            while b := f.read(chunk):
                yield b


def extract_class(cls: str) -> tuple[Path, bool]:
    """Decompress one class to data/extracted/<cls>.csv.

    Returns (path, truncated). `truncated` is True when the .gz file ends early
    (this happens with PortScan.csv.gz). In that case the rows that could be read
    are kept and the last incomplete line is dropped.
    """
    C.EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    out = C.EXTRACT_DIR / f"{cls}.csv"
    done = C.EXTRACT_DIR / f"{cls}.ok"
    if out.exists() and done.exists():
        return out, done.read_text().strip() == "truncated"

    parts = sorted(glob.glob(str(C.DATASET_DIR / cls / "*.csv.gz*")))
    if not parts:
        raise FileNotFoundError(f"no files for class {cls!r} in {C.DATASET_DIR / cls}")

    d = zlib.decompressobj(31)          # 31 = gzip format
    tail = b""                          # incomplete last line, kept until the next chunk
    truncated = False
    tmp = out.with_suffix(".part")
    with open(tmp, "wb") as fo:
        try:
            for b in _iter_bytes(parts):
                while b:
                    if d.eof:                       # a new gzip member starts
                        d = zlib.decompressobj(31)
                    data = tail + d.decompress(b)
                    b = d.unused_data if d.eof else b""
                    cut = data.rfind(b"\n") + 1
                    fo.write(data[:cut])
                    tail = data[cut:]
            truncated = not d.eof
        except zlib.error:
            truncated = True
        if tail and not truncated:
            fo.write(tail + b"\n")
    tmp.replace(out)
    done.write_text("truncated" if truncated else "ok")
    return out, truncated


def read_header(path: Path) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readline().strip().split(",")


def feature_columns(header: list[str]) -> list[str]:
    return [c for c in header if c not in C.DROP_COLS]


def column_renames(columns) -> dict[str, str]:
    """{name in this file: our name} for columns that only differ by CICFlowMeter version."""
    cols = set(columns)
    return {new: old for new, old in C.COLUMN_ALIASES.items() if new in cols and old not in cols}


def _contiguous_blocks(n: int, cap: int | None, rng: np.random.Generator, k: int = 20) -> np.ndarray:
    """Pick `cap` row indices out of `n` as k contiguous blocks spread over time (None = all)."""
    if cap is None or n <= cap:
        return np.arange(n)
    k = max(1, min(k, cap))
    block = cap // k
    seg = n / k
    idx = []
    for i in range(k):
        lo, hi = int(i * seg), int((i + 1) * seg)
        start = lo + int(rng.integers(0, max(1, hi - lo - block + 1)))
        idx.append(np.arange(start, min(start + block, n)))
    return np.concatenate(idx)


def load_class(cls: str, features: list[str], cap: int | None, rng: np.random.Generator) -> pd.DataFrame:
    """Return a time-ordered DataFrame with `features` (float32) for one class."""
    path, _ = extract_class(cls)
    header = read_header(path)
    rename = column_renames(header)
    file_name = {ours: theirs for theirs, ours in rename.items()}
    usecols = [file_name.get(f, f) for f in features] + [C.TIME_COL]
    missing = [c for c in usecols if c not in header]
    if missing:
        raise SystemExit(f"{cls}: columns not found in {path.name}: {missing}")
    df = pd.read_csv(path, usecols=usecols, engine="pyarrow").rename(columns=rename)
    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.dropna(subset=[C.TIME_COL]).sort_values(C.TIME_COL, kind="stable").reset_index(drop=True)

    df = df.iloc[_contiguous_blocks(len(df), cap, rng)].reset_index(drop=True)

    X = df[features].to_numpy(dtype=np.float64)
    X[~np.isfinite(X)] = 0.0                       # inf / NaN (e.g. Flow Byts/s with duration 0)
    X = np.clip(X, -1e12, 1e12).astype(np.float32)
    return pd.DataFrame(X, columns=features)


# ---------------------------------------------------------------- after preprocess.py
def load_meta() -> dict:
    import json
    path = C.PROCESSED_DIR / "meta.json"
    if not path.exists():
        raise SystemExit("processed data not found — run `python preprocess.py` first")
    return json.loads(path.read_text(encoding="utf-8"))


def load_split(name: str) -> pd.DataFrame:
    """name = 'train' | 'val' | 'test'  (time stream with features, label, burst)."""
    return pd.read_parquet(C.PROCESSED_DIR / f"{name}.parquet")
