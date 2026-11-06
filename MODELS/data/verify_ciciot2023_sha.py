"""
Check the downloaded CICIoT2023 files against the hashes published by Hugging Face.

Hugging Face gives two kinds of hash in its file list:
    - big files (Git LFS): SHA-256 of the file            -> "lfs.oid"
    - small files (plain git): git blob SHA-1              -> "oid"  = sha1("blob <size>\\0" + file bytes)
The script computes the same hash for every local file and compares. It only READS the data files.

    source /home/abhinav_iot/pqzta-venv/bin/activate
    cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA
    python MODELS/data/verify_ciciot2023_sha.py                      # all CSVs under CSV/CSV/
    python MODELS/data/verify_ciciot2023_sha.py --include ""         # every downloaded file of the repo

Note: this proves the files equal the Hugging Face copy. UNB publishes no hashes, so it cannot prove
equality with the official UNB files.
Only the Python standard library is used.

Saves: runs/verify_ciciot2023_sha_<YYYYMMDD_HHMMSS>/ run.log, config.json, results.json, sha256sums.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import download_ciciot2023_csv as dl                                   # noqa: E402  (same settings + helpers)

# ---------------------------------------------------------------- settings
DATA_DIR = dl.OUT_DIR                   # DataSet/CICIoT2023_csv
RUNS_DIR = dl.RUNS_DIR
SCRIPT_NAME = "verify_ciciot2023_sha"
HF_REPO, HF_REVISION = dl.HF_REPO, dl.HF_REVISION
INCLUDE = "CSV/CSV/"
CHUNK = 8 << 20                         # 8 MiB
SEED = 42


def hf_entries(log) -> list[dict]:
    url, entries = dl.HF_API.format(repo=HF_REPO, rev=HF_REVISION), []
    while url:
        with dl._request(url) as r:
            entries += json.loads(r.read().decode("utf-8"))
            nxt = [p.split(";")[0].strip(" <>") for p in r.headers.get("Link", "").split(",") if 'rel="next"' in p]
            url = nxt[0] if nxt else None
    log.info("Hugging Face %s: %d entries in the file list", HF_REPO, len(entries))
    return [e for e in entries if e.get("type") == "file"]


def file_hashes(path: Path) -> tuple[str, str, int]:
    """Return (sha256, git-blob-sha1, size) in one pass over the file."""
    size = path.stat().st_size
    s256, s1 = hashlib.sha256(), hashlib.sha1()
    s1.update(f"blob {size}\0".encode())
    with open(path, "rb") as f:
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            s256.update(buf)
            s1.update(buf)
    return s256.hexdigest(), s1.hexdigest(), size


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify CICIoT2023 downloads against Hugging Face hashes")
    ap.add_argument("--data", type=Path, default=DATA_DIR)
    ap.add_argument("--include", default=INCLUDE, help="only repo paths that start with this ('' = all)")
    ap.add_argument("--ext", nargs="+", default=[".csv"])
    args = ap.parse_args()

    random.seed(SEED)                                   # no randomness used; project rule
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    log = dl.setup_logging(run_dir)
    t0 = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    try:
        env = dl.log_environment(log)
        dl.write_json(run_dir / "config.json", {"script": SCRIPT_NAME, "data": str(args.data), "repo": HF_REPO,
                                                "revision": HF_REVISION, "include": args.include,
                                                "ext": args.ext, "environment": env})
        entries = [e for e in hf_entries(log)
                   if e["path"].startswith(args.include)
                   and any(e["path"].lower().endswith(x.lower()) for x in args.ext)]
        log.info("%d files to check in %s", len(entries), args.data)

        rows, sums = [], []
        for i, e in enumerate(entries, 1):
            path = args.data / e["path"]
            lfs = e.get("lfs") or {}
            want_size = lfs.get("size") or e.get("size")
            row = {"path": e["path"], "expected_bytes": want_size,
                   "hash_type": "sha256 (LFS)" if lfs else "git-sha1", "expected": lfs.get("oid") or e.get("oid")}
            if not path.exists():
                row["status"] = "MISSING"
            else:
                sha256, gitsha1, size = file_hashes(path)
                got = sha256 if lfs else gitsha1
                row.update(local_bytes=size, sha256=sha256, got=got)
                if size != want_size:
                    row["status"] = "SIZE MISMATCH"
                elif got != row["expected"]:
                    row["status"] = "HASH MISMATCH"
                else:
                    row["status"] = "OK"
                sums.append(f"{sha256}  {e['path']}")
            rows.append(row)
            if row["status"] != "OK" or i % 25 == 0 or i == len(entries):
                log.info("[%d/%d] %-14s %s", i, len(entries), row["status"], e["path"])

        # local files that are not in the Hugging Face list, and leftover .part files
        listed = {str((args.data / e["path"]).resolve()) for e in entries}
        sub = args.data / args.include if args.include else args.data
        extra = sorted(str(p.relative_to(args.data)) for p in sub.rglob("*")
                       if p.is_file() and str(p.resolve()) not in listed) if sub.exists() else []
        (run_dir / "sha256sums.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

        counts: dict = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        bad = [r for r in rows if r["status"] != "OK"]
        out.update(status="ok" if not bad else "error", checked=len(rows), counts=counts,
                   problems=bad, extra_local_files=extra, files=rows,
                   total_gb=round(sum(r.get("local_bytes", 0) for r in rows) / 1e9, 3))
        log.info("RESULT: %s | extra local files (not in HF list): %d", counts, len(extra))
        for x in extra[:20]:
            log.info("   extra: %s", x)
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t0, 1)
    dl.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK: all %d files match (%.1f min)", out["checked"], out["time_taken_s"] / 60)
        return 0
    log.error("FINISHED WITH PROBLEMS (see results.json -> problems)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
