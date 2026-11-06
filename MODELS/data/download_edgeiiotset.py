"""
Download the Edge-IIoTset dataset (Ferrag et al., IEEE Access 2022) from its public Kaggle copy, CLI only.

Kaggle lets anyone list and download a PUBLIC dataset without an account or API key:
    file list : https://www.kaggle.com/api/v1/datasets/list/<owner>/<dataset>
    archive   : https://www.kaggle.com/api/v1/datasets/download/<owner>/<dataset>   (one zip, ~1.75 GB)
Single-file downloads need a login (they return 404 without one), so the script downloads the whole
archive once (resumable), then unpacks ONLY the files you want (default: every .pcap = attack + normal)
into DataSet/Edge-IIoTset/ with the same folders as on Kaggle. The zip is kept (use --delete-zip to remove it).

    source /home/abhinav_iot/pqzta-venv/bin/activate
    cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA
    python MODELS/data/download_edgeiiotset.py --dry-run                 # list files + total size only
    python MODELS/data/download_edgeiiotset.py                           # download all .pcap files
    python MODELS/data/download_edgeiiotset.py --ext .pcap .csv          # PCAPs and CSVs

Safe by design (same rules as download_ciciot2023_csv.py):
    - complete files are skipped, never overwritten; a wrong-size existing file is reported, not replaced
    - unfinished downloads stay as <name>.part and resume on the next run
    - every unpacked file is checked against the size in the Kaggle file list and the zip's CRC
    - checks free disk space first; writes sha256sums.txt of every file so you can re-check later
Only the Python standard library is used.

Licence (from the dataset page): free for academic research; cite
M. A. Ferrag et al., "Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT
Applications for Centralized and Federated Learning", IEEE Access, 2022. Official source: IEEE DataPort,
DOI 10.21227/mbc1-1h68.

Saves: runs/download_edgeiiotset_<YYYYMMDD_HHMMSS>/ run.log, config.json, results.json, sha256sums.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
import time
import traceback
import urllib.parse
import zipfile
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import download_ciciot2023_csv as dl                                   # noqa: E402  (logging + download helpers)

# ---------------------------------------------------------------- settings
PROJECT_ROOT = dl.PROJECT_ROOT
OUT_DIR = PROJECT_ROOT / "DataSet" / "Edge-IIoTset"      # NEW folder
RUNS_DIR = dl.RUNS_DIR
SCRIPT_NAME = "download_edgeiiotset"
KAGGLE_DATASET = "mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot"
LIST_URL = "https://www.kaggle.com/api/v1/datasets/list/{ds}?pageSize=200"
ARCHIVE_URL = "https://www.kaggle.com/api/v1/datasets/download/{ds}"
ARCHIVE_NAME = "_kaggle_archive.zip"                     # saved inside OUT_DIR
EXTENSIONS = [".pcap"]
FREE_SPACE_MARGIN_GB = 5
SEED = 42


def list_kaggle(ds: str, log) -> list[dict]:
    """All files of a public Kaggle dataset: [{'path', 'bytes'}]. Follows nextPageToken pages."""
    files, token, page = [], None, 0
    while True:
        url = LIST_URL.format(ds=ds) + (f"&pageToken={urllib.parse.quote(token)}" if token else "")
        with dl._request(url) as r:
            data = json.loads(r.read().decode("utf-8"))
        page += 1
        for f in data.get("datasetFiles") or data.get("files") or []:
            path = f.get("name") or f.get("path") or f.get("ref")
            if path:
                files.append({"path": path, "bytes": f.get("totalBytes") or f.get("size")})
        token = data.get("nextPageToken") or None
        if not token or not data.get("hasNextPageToken", True):
            break
        if page > 100:
            raise RuntimeError("more than 100 pages in the Kaggle file list: stopping")
    log.info("Kaggle %s: %d files in %d page(s)", ds, len(files), page)
    return files


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(8 << 20), b""):
            h.update(buf)
    return h.hexdigest()


def archive_size(url: str) -> int | None:
    """Size of the archive. HEAD returns 404 on Kaggle, so ask for 1 byte and read Content-Range."""
    try:
        with dl._request(url, headers={"Range": "bytes=0-0"}) as r:
            cr = r.headers.get("Content-Range", "")
            return int(cr.rsplit("/", 1)[-1]) if "/" in cr else None
    except Exception:
        return None


def extract_one(z: zipfile.ZipFile, member: zipfile.ZipInfo, dest: Path) -> None:
    """Unpack one zip member to dest via a .part file (CRC is checked by zipfile while reading)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    with z.open(member) as src, open(part, "wb") as out:
        shutil.copyfileobj(src, out, 8 << 20)
    part.rename(dest)


def main() -> int:
    ap = argparse.ArgumentParser(description="Download Edge-IIoTset from Kaggle (no login)")
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    ap.add_argument("--ext", nargs="+", default=EXTENSIONS, help="file endings to download (default .pcap)")
    ap.add_argument("--include", default="", help="only files whose path contains this text")
    ap.add_argument("--limit", type=int, default=0, help="only the first N files (0 = all)")
    ap.add_argument("--dry-run", action="store_true", help="list files and sizes, download nothing")
    ap.add_argument("--delete-zip", action="store_true", help="delete the archive after a fully OK unpack")
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
        config = {"script": SCRIPT_NAME, "kaggle_dataset": KAGGLE_DATASET, "out_dir": str(args.out),
                  "ext": args.ext, "include": args.include, "limit": args.limit, "dry_run": args.dry_run,
                  "environment": env}
        dl.write_json(run_dir / "config.json", config)
        log.info("settings: %s", {k: v for k, v in config.items() if k != "environment"})

        everything = list_kaggle(KAGGLE_DATASET, log)
        dl.write_json(run_dir / "kaggle_file_list.json", everything)          # full list, for the record
        files = [f for f in everything if any(f["path"].lower().endswith(e.lower()) for e in args.ext)
                 and args.include.lower() in f["path"].lower()]
        files.sort(key=lambda f: f["path"])
        if args.limit:
            files = files[: args.limit]
        if not files:
            raise SystemExit("no matching files (check --ext / --include)")
        total = sum(f["bytes"] or 0 for f in files)
        log.info("%d files selected, total %.2f GB", len(files), total / 1e9)
        for f in files:
            log.info("   %-80s %10.1f MB", f["path"], (f["bytes"] or 0) / 1e6)
        out.update(n_files=len(files), total_gb=round(total / 1e9, 3))

        if args.dry_run:
            out.update(status="ok", files=files, note="dry run")
        else:
            args.out.mkdir(parents=True, exist_ok=True)
            url = ARCHIVE_URL.format(ds=KAGGLE_DATASET)
            zsize = archive_size(url)
            free = shutil.disk_usage(args.out).free
            log.info("archive %.2f GB (zip), selected files %.2f GB unpacked, free disk %.1f GB",
                     (zsize or 0) / 1e9, total / 1e9, free / 1e9)
            if (zsize or 0) + total + FREE_SPACE_MARGIN_GB * 1e9 > free:
                raise SystemExit(f"not enough disk space: free {free / 1e9:.1f} GB")

            # 1) the whole archive (resumable; skipped if already complete)
            zpath = args.out / ARCHIVE_NAME
            log.info("downloading archive -> %s", zpath)
            zres = dl.download(url, zpath, zsize, log)
            out["archive"] = zres
            if not zpath.exists():
                raise SystemExit(f"archive download failed: {zres['status']} (run again to resume)")

            # 2) unpack only the selected files
            results, sums = [], []
            with zipfile.ZipFile(zpath) as z:
                by_name = {m.filename: m for m in z.infolist() if not m.is_dir()}
                by_base: dict = {}
                for m in by_name.values():
                    by_base.setdefault(Path(m.filename).name, []).append(m)
                for i, f in enumerate(files, 1):
                    dest = (args.out / f["path"]).resolve()
                    if args.out.resolve() not in dest.parents:
                        raise ValueError(f"unsafe path in file list: {f['path']}")
                    log.info("[%d/%d] %s", i, len(files), f["path"])
                    row = {"path": f["path"], "expected_bytes": f["bytes"], "file": str(dest)}
                    member = by_name.get(f["path"]) or (by_base.get(Path(f["path"]).name) or [None])[0]
                    if member is None:
                        row["status"] = "FAILED: not found inside the archive"
                    elif dest.exists():
                        have = dest.stat().st_size
                        row.update(bytes=have, status="skipped (already complete)" if have == member.file_size
                                   else f"SIZE MISMATCH: local {have} vs zip {member.file_size}; not overwritten")
                    else:
                        try:
                            extract_one(z, member, dest)
                            have = dest.stat().st_size
                            row.update(bytes=have, status="unpacked")
                            if f["bytes"] and have != f["bytes"]:
                                row["status"] = f"SIZE MISMATCH: got {have} vs Kaggle list {f['bytes']}"
                        except Exception as e:                 # bad CRC / broken zip
                            row["status"] = f"FAILED: {e}"
                    if row["status"].startswith(("FAILED", "SIZE")):
                        log.error("   %s", row["status"])
                    elif dest.exists():
                        row["sha256"] = sha256(dest)
                        sums.append(f"{row['sha256']}  {f['path']}")
                    results.append(row)
                    dl.write_json(run_dir / "results.json", {**out, "files": results})   # progress as we go
            (run_dir / "sha256sums.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
            bad = [r for r in results if r["status"].startswith(("FAILED", "SIZE"))]
            out.update(status="ok" if not bad else "error", files=results, n_failed=len(bad), problems=bad,
                       unpacked_gb=round(sum(r.get("bytes") or 0 for r in results) / 1e9, 3))
            if args.delete_zip and not bad:
                zpath.unlink()
                log.info("archive deleted (--delete-zip)")
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t0, 1)
    dl.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.1f min)", out["time_taken_s"] / 60)
        return 0
    log.error("FINISHED WITH PROBLEMS (see results.json -> problems)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
