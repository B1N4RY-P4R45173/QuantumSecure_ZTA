"""
Download the CICIoT2023 CSV files (UNB / Canadian Institute for Cybersecurity).

The official download is behind a form:
    http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/
Fill in the form in a browser. You then get a folder page (a directory listing) for the dataset.
Copy the URL of that page (the root folder, or the CSV folder) and give it to this script with --base-url.
The script reads the listing, finds every .csv file (also in subfolders), and downloads it.

    # 1) see what would be downloaded and how big it is (downloads nothing)
    python MODELS/data/download_ciciot2023_csv.py --base-url "<URL from the form>" --dry-run
    # 2) download
    python MODELS/data/download_ciciot2023_csv.py --base-url "<URL from the form>"
    # or: a text file with one file URL per line
    python MODELS/data/download_ciciot2023_csv.py --url-list my_urls.txt
    # or (no form, CLI only): the public Hugging Face copy, per-class CSVs only (about 8.9 GB)
    python MODELS/data/download_ciciot2023_csv.py --hf --include CSV/CSV/ --dry-run

Safe by design:
    - existing complete files are skipped, never overwritten
    - an unfinished download is kept as <name>.part and resumed on the next run
    - stops before downloading if the disk does not have enough free space
Only the Python standard library is used (any environment works; pqzta-venv is fine).

Note: CICIoT2023 CSV features are made with DPKT (packet-window features), NOT CICFlowMeter.
Our TRUST Lab models cannot use them directly; for that we need the PCAP files.

Saves: runs/download_ciciot2023_csv_<YYYYMMDD_HHMMSS>/ run.log, config.json, results.json (file list, sizes, status)
Data:  OUT_DIR below (default DataSet/CICIoT2023_csv/), same subfolder layout as the server.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import random
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

# ---------------------------------------------------------------- settings
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
OUT_DIR = PROJECT_ROOT / "DataSet" / "CICIoT2023_csv"    # NEW folder; existing DataSet folders are not touched
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "download_ciciot2023_csv"
FORM_URL = "http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/"
HF_REPO = "bencorn/CIC-IoT-2023"   # public Hugging Face copy (unofficial); same folders as UNB: CSV/, PCAP/, ...
HF_REVISION = "main"
HF_API = "https://huggingface.co/api/datasets/{repo}/tree/{rev}?recursive=true"
HF_FILE = "https://huggingface.co/datasets/{repo}/resolve/{rev}/"
EXTENSIONS = [".csv"]          # change with --ext (for example --ext .csv .zip)
MAX_DEPTH = 4                  # how deep to follow subfolders in the listing
TIMEOUT_S = 60
RETRIES = 5
CHUNK = 1 << 20                # 1 MiB
FREE_SPACE_MARGIN_GB = 5       # keep at least this much free after the download
USER_AGENT = "Mozilla/5.0 (research download script)"
SEED = 42


# ---------------------------------------------------------------- logging
def setup_logging(run_dir: Path) -> logging.Logger:
    log = logging.getLogger(SCRIPT_NAME)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    for h in (logging.StreamHandler(sys.stdout), logging.FileHandler(run_dir / "run.log", encoding="utf-8")):
        h.setFormatter(fmt)
        log.addHandler(h)
    return log


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def log_environment(log: logging.Logger) -> dict:
    env = {"python": sys.version.split()[0], "executable": sys.executable, "platform": platform.platform()}
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=20)
        env["gpus"] = [l.strip() for l in out.stdout.splitlines() if l.strip()] or "none"
    except Exception as e:                     # no GPU is fine: this script does not need one
        env["gpus"] = f"not available ({e.__class__.__name__})"
    for k, v in env.items():
        log.info("%s: %s", k, v)
    return env


# ---------------------------------------------------------------- web helpers
def _request(url: str, method: str = "GET", headers: dict | None = None):
    h = {"User-Agent": USER_AGENT}
    h.update(headers or {})
    return urllib.request.urlopen(urllib.request.Request(url, method=method, headers=h), timeout=TIMEOUT_S)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def list_files(base_url: str, exts: list[str], log: logging.Logger) -> list[str]:
    """Walk a directory-listing page (Apache/nginx style) and return file URLs with the wanted extensions."""
    if not base_url.endswith("/"):
        base_url += "/"
    found, seen, todo = [], set(), [(base_url, 0)]
    while todo:
        url, depth = todo.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            with _request(url) as r:
                ctype = r.headers.get("Content-Type", "")
                html = r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            log.warning("cannot open %s (HTTP %s)", url, e.code)
            continue
        if "html" not in ctype:
            log.warning("%s is not an HTML listing (%s)", url, ctype)
            continue
        if "<form" in html.lower() and depth == 0 and "index of" not in html.lower():
            raise SystemExit(f"{url} is the download FORM, not a folder listing. Fill the form in a browser "
                             "and pass the folder URL you get afterwards with --base-url.")
        p = _Links()
        p.feed(html)
        for href in p.links:
            if href.startswith(("?", "#", "mailto:", "javascript:")):
                continue
            full = urllib.parse.urljoin(url, href)
            if not full.startswith(base_url) or full == url:      # stay inside the given folder, no parent links
                continue
            if full.endswith("/"):
                if depth < MAX_DEPTH:
                    todo.append((full, depth + 1))
            elif any(urllib.parse.unquote(full).lower().endswith(e.lower()) for e in exts):
                found.append(full)
    return sorted(set(found))


def list_hf(repo: str, rev: str, exts: list[str], log: logging.Logger) -> tuple[str, list[str], dict]:
    """List files of a public Hugging Face dataset repo with the API (no login). Returns base URL, URLs, sizes."""
    base = HF_FILE.format(repo=repo, rev=rev)
    url, entries = HF_API.format(repo=repo, rev=rev), []
    while url:                                          # the API may split long lists into pages (Link: next)
        with _request(url) as r:
            entries += json.loads(r.read().decode("utf-8"))
            nxt = [p.split(";")[0].strip(" <>") for p in r.headers.get("Link", "").split(",") if 'rel="next"' in p]
            url = nxt[0] if nxt else None
    urls, sizes = [], {}
    for e in entries:
        path = e.get("path", "")
        if e.get("type") == "file" and any(path.lower().endswith(x.lower()) for x in exts):
            u = base + urllib.parse.quote(path)
            urls.append(u)
            sizes[u] = (e.get("lfs") or {}).get("size") or e.get("size")
    log.info("Hugging Face %s: %d entries, %d matching files", repo, len(entries), len(urls))
    return base, sorted(urls), sizes


def remote_size(url: str) -> int | None:
    try:
        with _request(url, method="HEAD") as r:
            n = r.headers.get("Content-Length")
            return int(n) if n else None
    except Exception:
        return None


def local_path(url: str, base_url: str | None, out_dir: Path) -> Path:
    if base_url and url.startswith(base_url):
        rel = urllib.parse.unquote(url[len(base_url):].lstrip("/"))
    else:
        rel = urllib.parse.unquote(Path(urllib.parse.urlparse(url).path).name)
    p = (out_dir / rel).resolve()
    if out_dir.resolve() not in p.parents:
        raise ValueError(f"unsafe file path from server: {rel}")
    return p


def download(url: str, dest: Path, size: int | None, log: logging.Logger) -> dict:
    res = {"url": url, "file": str(dest), "expected_bytes": size}
    if dest.exists():
        have = dest.stat().st_size
        if size is None or have == size:
            res.update(status="skipped (already complete)", bytes=have)
        else:
            res.update(status=f"SIZE MISMATCH: local {have} vs server {size}; not overwritten", bytes=have)
            log.warning("%s: %s", dest.name, res["status"])
        return res
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    t0 = time.time()
    for attempt in range(1, RETRIES + 1):
        start = part.stat().st_size if part.exists() else 0
        if size is not None and start > size:            # broken partial file: start again
            part.unlink()
            start = 0
        if size is not None and start == size:
            break
        try:
            headers = {"Range": f"bytes={start}-"} if start else {}
            with _request(url, headers=headers) as r:
                resumed = start > 0 and r.status == 206
                mode = "ab" if resumed else "wb"
                with open(part, mode) as f:
                    while True:
                        buf = r.read(CHUNK)
                        if not buf:
                            break
                        f.write(buf)
            if size is None or part.stat().st_size == size:
                break
            log.warning("%s: incomplete (%d of %d bytes), retry %d", dest.name, part.stat().st_size, size, attempt)
        except Exception as e:
            log.warning("%s: attempt %d failed: %s", dest.name, attempt, e)
            time.sleep(min(60, 5 * attempt))
    got = part.stat().st_size if part.exists() else 0
    if part.exists() and (size is None or got == size):
        part.rename(dest)
        mb_s = got / 1e6 / max(time.time() - t0, 1e-6)
        res.update(status="downloaded", bytes=got, mb_per_s=round(mb_s, 2))
        log.info("OK %s (%.1f MB, %.1f MB/s)", dest.name, got / 1e6, mb_s)
    else:
        res.update(status="FAILED (partial kept as .part; run again to resume)", bytes=got)
        log.error("FAILED %s after %d attempts", dest.name, RETRIES)
    return res


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Download CICIoT2023 CSV files")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--base-url", help="folder URL you get after filling the CIC download form")
    src.add_argument("--url-list", type=Path, help="text file: one file URL per line")
    src.add_argument("--hf", action="store_true", help=f"use the public Hugging Face copy ({HF_REPO}), no form")
    ap.add_argument("--out", type=Path, default=OUT_DIR, help=f"where to save (default {OUT_DIR})")
    ap.add_argument("--ext", nargs="+", default=EXTENSIONS, help="file endings to download")
    ap.add_argument("--include", default="", help="only files whose URL contains this text (e.g. CSV)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N files (0 = all); good for a test")
    ap.add_argument("--dry-run", action="store_true", help="list files and sizes, download nothing")
    args = ap.parse_args()

    random.seed(SEED)                                   # no randomness is used; set for the project rule
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    log = setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    try:
        env = log_environment(log)
        config = {"script": SCRIPT_NAME, "base_url": args.base_url, "url_list": str(args.url_list or ""),
                  "hf_repo": HF_REPO if args.hf else "", "hf_revision": HF_REVISION if args.hf else "",
                  "out_dir": str(args.out), "ext": args.ext, "include": args.include, "limit": args.limit,
                  "dry_run": args.dry_run, "form_url": FORM_URL, "environment": env}
        write_json(run_dir / "config.json", config)
        log.info("settings: %s", {k: v for k, v in config.items() if k != "environment"})

        known_sizes: dict = {}
        if args.hf:
            base, urls, known_sizes = list_hf(HF_REPO, HF_REVISION, args.ext, log)
        elif args.base_url:
            base = args.base_url if args.base_url.endswith("/") else args.base_url + "/"
            urls = list_files(base, args.ext, log)
        else:
            base = None
            urls = [l.strip() for l in args.url_list.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
        if args.include:
            urls = [u for u in urls if args.include.lower() in urllib.parse.unquote(u).lower()]
        if args.limit:
            urls = urls[: args.limit]
        if not urls:
            raise SystemExit("no matching files found (check the URL, --ext and --include)")

        sizes = {u: known_sizes.get(u) or remote_size(u) for u in urls}
        known = sum(s for s in sizes.values() if s)
        log.info("%d files, total %.2f GB (%d without a size from the server)",
                 len(urls), known / 1e9, sum(1 for s in sizes.values() if s is None))
        for u in urls:
            log.info("   %s  %s", urllib.parse.unquote(u.rsplit("/", 1)[-1]),
                     f"{sizes[u] / 1e6:.1f} MB" if sizes[u] else "size unknown")
        out.update({"n_files": len(urls), "total_gb": round(known / 1e9, 3)})

        if args.dry_run:
            out.update(status="ok", files=[{"url": u, "bytes": sizes[u]} for u in urls], note="dry run")
        else:
            args.out.mkdir(parents=True, exist_ok=True)
            todo_bytes = sum(s for u, s in sizes.items() if s and not local_path(u, base, args.out).exists())
            free = shutil.disk_usage(args.out).free
            log.info("free disk %.1f GB, still to download %.1f GB", free / 1e9, todo_bytes / 1e9)
            if todo_bytes + FREE_SPACE_MARGIN_GB * 1e9 > free:
                raise SystemExit(f"not enough disk space: need {todo_bytes / 1e9:.1f} GB + "
                                 f"{FREE_SPACE_MARGIN_GB} GB margin, free {free / 1e9:.1f} GB")
            results = []
            for i, u in enumerate(urls, 1):
                dest = local_path(u, base, args.out)
                log.info("[%d/%d] %s", i, len(urls), dest.name)
                results.append(download(u, dest, sizes[u], log))
                write_json(run_dir / "results.json", {**out, "files": results})   # progress saved as we go
            failed = [r for r in results if r["status"].startswith(("FAILED", "SIZE"))]
            out.update(status="ok" if not failed else "error", files=results, n_failed=len(failed),
                       downloaded_gb=round(sum(r.get("bytes", 0) for r in results) / 1e9, 3))
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.1f min)", out["time_taken_s"] / 60)
        return 0
    log.error("FINISHED WITH PROBLEMS (see results.json)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
