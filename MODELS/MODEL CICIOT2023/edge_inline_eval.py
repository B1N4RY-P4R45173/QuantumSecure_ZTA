"""
Test the detection architecture on Edge-IIoTset (test dataset 1, never seen in training):

    LAYER 1  PREVENT : Suricata "inline" (simulated): a flow is DROPPED from its first THREATS alert on
    LAYER 2  DETECT  : packets that pass -> CICIoT2023 features (10 packets per row) -> BAL_MS (+ FLAT)
    LAYER 3/4 RESPOND: ML alert with P(attack) >= QUARANTINE_P -> quarantine the row's main source IP
                       for QUARANTINE_S seconds (its later packets are dropped)

Nothing is retrained. BAL_MS / FLAT come from train_ciciot2023.py (MODEL_RUN below).

Features: the 39 CICIoT2023 features are rebuilt here EXACTLY like CIC's own script
(Supplementary Materials/pcap2csv/Feature_extraction.py, read 2026-11-04): one row = 10 consecutive
IPv4/ARP packets; per-packet values averaged; flag counts summed; Tot sum/Min/Max/AVG/Std/Variance of frame
sizes; Rate = packets / time span; IAT = mean gap between packets; Protocol Type = most common protocol;
pcaps split every ~10 MB like "tcpdump -C 10" (rows and IAT restart there). CIC quirks are kept on purpose
(LLC = 1 for every IPv4 packet, SMTP only for TCP, IRC = port 21, fragments have no TCP/UDP).
A small pcap/pcapng reader is built in, so dpkt/scapy are not needed.

Labels (Edge-IIoTset gives labels in its CSVs, not in the pcaps): for every attack pcap the script reads the
matching CSV from the Kaggle archive and marks a packet as attack if its IP pair (src, dst) is labelled
attack more often than normal there. If that fails for a file, every packet of that attack pcap counts as
attack (logged as label_mode=file). Normal-traffic pcaps are all normal. A row is attack if >= 50% of its
packets are attack.

Results:
    - ML alone (rows): detection, false alarms, precision, F1, right category, per attack file
    - packet level: Suricata ALL / THREATS alone, BAL_MS alone, FLAT alone, and the COMBINED pipeline:
      share of attack packets blocked by Suricata, quarantined by ML, only alerted, or that REACHED the resource;
      normal packets wrongly blocked
    - time to first block per attack file; Suricata time and RAM per pcap

Simplifications (written in the report): Suricata runs offline (IDS mode on the pcap) and its THREATS alerts
are used as drops; the ML runs once on the packets Suricata let through (packets removed later by quarantine
are not re-fed to the ML); the trust score itself is not simulated.

    source /home/abhinav_iot/pqzta-venv/bin/activate
    cd /home/abhinav_iot/ZEROTRUST/QuantumSecure_ZTA
    python "MODELS/MODEL CICIOT2023/edge_inline_eval.py" --quick            # 200k packets per pcap
    python "MODELS/MODEL CICIOT2023/edge_inline_eval.py"                    # everything

Needs: pqzta-venv (pandas, numpy, lightgbm, psutil, matplotlib) and the "suricata" command (installed earlier).
Saves: runs/edge_inline_eval_<YYYYMMDD_HHMMSS>/ run.log, config.json, results.json, REPORT.md,
       per_file.csv, rows.parquet (predictions, no features), charts/, suricata/<pcap>/eve.json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import traceback
import zipfile
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import train_ciciot2023 as tc                                           # noqa: E402  (build_X, logging, ...)

# ---------------------------------------------------------------- settings
PROJECT_ROOT = HERE.parent.parent
EDGE_DIR = PROJECT_ROOT / "DataSet" / "Edge-IIoTset"                  # pcaps (any depth)
EDGE_ZIP = EDGE_DIR / "_kaggle_archive.zip"                           # has the label CSVs
MODEL_RUN = PROJECT_ROOT / "runs" / "train_ciciot2023_20261102_141609"
MODELS = ["BAL_MS", "FLAT"]                                           # first one = the pipeline model
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "edge_inline_eval"
SEED = 42

ROW_PACKETS = 10                     # CIC: n_rows = 10
SPLIT_BYTES = 10_000_000             # CIC: tcpdump -C 10 (10 MB sub-files)
ROW_ATTACK_SHARE = 0.5               # row = attack if >= 50% of its packets are attack
ALERT_P = 0.5                        # ML alert (lowers trust)
QUARANTINE_P = 0.9                   # ML direct quarantine (layer 3 rule)
QUARANTINE_S = 300                   # quarantine time, seconds
QUARANTINE_MIN_HITS = 3              # quarantine only after >= 3 qualifying rows from the same source ...
QUARANTINE_HIT_WINDOW_S = 10         # ... within 10 s (one false row must not block a sensor; run 160130:
                                     # single-row quarantine wrongly blocked 13% of normal packets)
SWEEP_MIN_HITS = [1, 2, 3, 5, 8]     # quarantine sweep (charts 02-04): every combination is replayed on the
SWEEP_QUARANTINE_S = [30, 60, 120, 300, 600]   # same detector outputs (no new Suricata / training)
# chart colors (validated default palette of the dataviz guide)
C_SURFACE, C_INK, C_INK2, C_GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
C_SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
C_BLUE_RAMP = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
QUARANTINE_NEEDS_AE = True           # quarantine only when ML P>=QUARANTINE_P AND the autoencoder agrees
                                     # (run 20261104_154824: ML alone wrongly quarantined 12% of Water_Level/Modbus)
QUICK_PACKETS = 200_000              # --quick: first N packets per pcap

SURICATA_RULES = "/var/lib/suricata/rules/suricata.rules"
SURICATA_RUNMODE = "single"          # 1 worker thread, like a small gateway. "autofp" on 128 cores started
                                     # ~128 workers and failed: "stream.memcap ... Engine initialization failed"
SURICATA_MEMCAP = {"stream.memcap": "2gb", "stream.reassembly.memcap": "2gb", "flow.memcap": "1gb"}
SURICATA_JOBS = 6                    # pcaps at the same time
SHIFT_SAMPLE_ROWS = 200_000          # CICIoT2023 Benign rows used for the feature-shift check
CALIBRATE_SHARE = 0.30               # first 30% (by time) of every NORMAL pcap = the site's learning period
CALIBRATE_VAL_SHARE = 0.20           # last 20% of the learning period = held out (AE threshold, early stop)
PIPELINE_MODEL = "BAL_MS_cal"        # ML model used in the pipeline after calibration (or FLAT_cal)
MIX_ATTACK_ROWS_PER_FILE = 20_000    # mixed test: max Edge attack rows taken from each attack pcap
# Edge-IIoTset attackers are inside the lab network, so EXTERNAL_NET = any (else most ET rules stay silent)
HOME_NET = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
EXTERNAL_NET = "any"
NOT_THREAT_PREFIXES = ("SURICATA ", "ET INFO", "ET POLICY")           # same split as the CIC-IDS2017 test
PARSE_JOBS = 12

# Edge-IIoTset pcap name (lower case, letters/digits only) -> our category
EDGE_CATEGORY = [("ddos", "Flood DoS/DDoS"), ("sqlinjection", "Web attack"), ("xss", "Web attack"),
                 ("uploading", "Web attack"), ("password", "Brute force"), ("portscanning", "Scan / Recon"),
                 ("vulnerability", "Scan / Recon"), ("fingerprinting", "Scan / Recon"),
                 ("backdoor", "C2 / Bot"), ("mitm", "Spoofing / MITM"),
                 ("ransomware", "Ransomware (not in training)")]

MEAN_COLS = ["Header_Length", "Time_To_Live", "fin_flag_number", "syn_flag_number", "rst_flag_number",
             "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
             "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP",
             "IGMP", "IPv", "LLC", "IAT"]
COUNT_COLS = {"ack_count": "ack_flag_number", "syn_count": "syn_flag_number",
              "fin_count": "fin_flag_number", "rst_count": "rst_flag_number"}


# ---------------------------------------------------------------- pcap reading (stdlib)
def iter_pcap(path: Path, max_packets: int = 0):
    """Yield (ts, linktype, frame bytes) from a pcap or pcapng file."""
    n = 0
    with open(path, "rb", buffering=1 << 22) as f:
        head = f.read(4)
        if head == b"\x0a\x0d\x0d\x0a":
            for item in _iter_pcapng(f, head):
                yield item
                n += 1
                if max_packets and n >= max_packets:
                    return
            return
        magic = struct.unpack("<I", head)[0]
        table = {0xA1B2C3D4: ("<", 1e6), 0xD4C3B2A1: (">", 1e6), 0xA1B23C4D: ("<", 1e9), 0x4D3CB2A1: (">", 1e9)}
        if magic not in table:
            raise ValueError(f"{path.name}: not a pcap/pcapng file")
        e, div = table[magic]
        linktype = struct.unpack(e + "HHiIII", f.read(20))[5]
        hdr = struct.Struct(e + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _ = hdr.unpack(h)
            buf = f.read(incl)
            if len(buf) < incl:
                return
            yield sec + frac / div, linktype, buf
            n += 1
            if max_packets and n >= max_packets:
                return


def _iter_pcapng(f, first):
    e, links, res, pending = "<", [], [], first
    while True:
        bt = pending if pending is not None else f.read(4)
        pending = None
        if len(bt) < 4:
            return
        lb = f.read(4)
        if len(lb) < 4:
            return
        if bt == b"\x0a\x0d\x0d\x0a":                                   # section header
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            f.read(struct.unpack(e + "I", lb)[0] - 12)
            links, res = [], []
            continue
        btype, blen = struct.unpack(e + "I", bt)[0], struct.unpack(e + "I", lb)[0]
        body = f.read(blen - 8)
        if btype == 1:                                                  # interface description
            links.append(struct.unpack(e + "H", body[0:2])[0])
            r, i, opts = 1e-6, 8, body[:-4]
            while i + 4 <= len(opts):
                code, ln = struct.unpack(e + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = opts[i + 4]
                    r = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + ln + (-ln % 4)
            res.append(r)
        elif btype == 6 and links:                                      # enhanced packet
            iface, th, tl, cap, _ = struct.unpack(e + "IIIII", body[:20])
            yield ((th << 32) | tl) * res[iface], links[iface], body[20:20 + cap]


def parse_packets(path: Path, max_packets: int) -> pd.DataFrame:
    """One row per IPv4/ARP packet with the raw values CIC's script uses."""
    cols = {k: [] for k in ("ts", "size", "is_arp", "proto", "ttl", "tcp", "udp", "hdr", "tflags",
                            "sport", "dport", "src", "dst")}
    ntoa, ip_cache = socket.inet_ntoa, {}

    def ip(b):
        s = ip_cache.get(b)
        if s is None:
            s = ip_cache[b] = ntoa(b)
        return s

    for ts, lt, buf in iter_pcap(path, max_packets):
        if lt == 1:                                                     # Ethernet (+ VLAN tags)
            if len(buf) < 14:
                continue
            et, off = (buf[12] << 8) | buf[13], 14
            while et in (0x8100, 0x88A8) and len(buf) >= off + 4:
                et, off = (buf[off + 2] << 8) | buf[off + 3], off + 4
        elif lt == 113:                                                 # Linux cooked
            if len(buf) < 16:
                continue
            et, off = (buf[14] << 8) | buf[15], 16
        elif lt == 276:                                                 # Linux cooked v2
            if len(buf) < 20:
                continue
            et, off = (buf[0] << 8) | buf[1], 20
        elif lt in (101, 228, 12, 14):                                  # raw IP
            if not buf:
                continue
            et, off = (0x0800 if buf[0] >> 4 == 4 else 0x86DD), 0
        else:
            continue
        if et == 0x0806:                                                # ARP
            if len(buf) < off + 28:
                continue
            vals = (ts, len(buf), 1, 0, 0, 0, 0, 0, 0, 0, 0, ip(buf[off + 14:off + 18]), ip(buf[off + 24:off + 28]))
        elif et == 0x0800:                                              # IPv4 (IPv6 has no row in CIC's script)
            if len(buf) < off + 20 or buf[off] >> 4 != 4:
                continue
            ihl = (buf[off] & 0x0F) * 4
            total = (buf[off + 2] << 8) | buf[off + 3]
            frag = ((buf[off + 6] << 8) | buf[off + 7]) & 0x3FFF          # MF flag + offset
            p, ttl = buf[off + 9], buf[off + 8]
            l4 = buf[off + ihl: off + max(total, ihl)]
            tcp = udp = hdr = tfl = sp = dp = 0
            if not frag and p == 6 and len(l4) >= 20:
                doff = (l4[12] >> 4) * 4
                if doff >= 20 and len(l4) >= doff:
                    tcp, hdr, tfl = 1, doff, l4[13]
                    sp, dp = (l4[0] << 8) | l4[1], (l4[2] << 8) | l4[3]
            elif not frag and p == 17 and len(l4) >= 8:
                udp, hdr = 1, 8
                sp, dp = (l4[0] << 8) | l4[1], (l4[2] << 8) | l4[3]
            vals = (ts, len(buf), 0, p, ttl, tcp, udp, hdr, tfl, sp, dp,
                    ip(buf[off + 12:off + 16]), ip(buf[off + 16:off + 20]))
        else:
            continue
        for k, v in zip(cols, vals):
            cols[k].append(v)
    df = pd.DataFrame(cols)
    for k, t in (("ts", np.float64), ("size", np.int32), ("is_arp", np.int8), ("proto", np.int16),
                 ("ttl", np.int16), ("tcp", np.int8), ("udp", np.int8), ("hdr", np.int16), ("tflags", np.int16),
                 ("sport", np.int32), ("dport", np.int32)):
        df[k] = df[k].astype(t)
    return df


# ---------------------------------------------------------------- labels
def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower()).replace("attacks", "").replace("attack", "")


def edge_category(pcap: Path) -> str:
    if "normal" in str(pcap.parent).lower():
        return tc.NORMAL
    n = norm(pcap.stem)
    for key, cat in EDGE_CATEGORY:
        if key in n:
            return cat
    return "Unknown attack (not mapped)"


def pair_keys(a: pd.Series, b: pd.Series) -> pd.Series:
    a, b = a.astype(str), b.astype(str)
    return pd.Series(np.where(a < b, a + "|" + b, b + "|" + a), index=a.index)


def attack_pairs_from_zip(pcap: Path, zip_path: Path) -> tuple[set | None, str]:
    """IP pairs labelled attack (more often than normal) in the Edge-IIoTset CSV that matches this pcap."""
    if not zip_path.exists():
        return None, "no archive"
    with zipfile.ZipFile(zip_path) as z:
        target = norm(pcap.stem)
        cands = [m for m in z.namelist() if m.lower().endswith(".csv") and "attack traffic" in m.lower()]
        scored = []
        for m in cands:
            n = norm(Path(m).stem)
            if n and (n in target or target in n or n[:5] == target[:5]):
                scored.append((len(os.path.commonprefix([n, target])), m))
        if not scored:
            return None, "no matching csv"
        member = max(scored)[1]
        with z.open(member) as fh:
            head = pd.read_csv(fh, nrows=0).columns
        low = {c.lower(): c for c in head}
        pick = lambda *names: next((low[n] for n in names if n in low), None)   # noqa: E731
        src, dst = pick("ip.src_host", "ip.src"), pick("ip.dst_host", "ip.dst")
        asrc, adst = pick("arp.src.proto_ipv4"), pick("arp.dst.proto_ipv4")
        lab = pick("attack_label", "label")
        if not (src and dst and lab):
            return None, f"{Path(member).name}: columns not found"
        use = [c for c in (src, dst, asrc, adst, lab) if c]
        counts: dict = {}
        with z.open(member) as fh:
            for ch in pd.read_csv(fh, usecols=use, dtype=str, chunksize=500_000):
                s, d = ch[src].fillna("0"), ch[dst].fillna("0")
                if asrc and adst:
                    bad = s.isin(["0", "0.0", "", "nan"])
                    s = s.where(~bad, ch[asrc].fillna("0"))
                    d = d.where(~bad, ch[adst].fillna("0"))
                key = pair_keys(s, d)
                att = pd.to_numeric(ch[lab], errors="coerce").fillna(0).to_numpy() > 0
                for k, v in key[att].value_counts().items():
                    c = counts.setdefault(k, [0, 0]); c[0] += int(v)
                for k, v in key[~att].value_counts().items():
                    c = counts.setdefault(k, [0, 0]); c[1] += int(v)
        pairs = {k for k, (a, n) in counts.items() if a > n}
        return pairs, f"csv {Path(member).name} ({len(pairs):,} attack pairs)"


def load_file(args_tuple) -> dict:
    """Worker: parse one pcap + label its packets."""
    pcap, max_packets, zip_path = args_tuple
    t0 = time.time()
    cat = edge_category(pcap)
    pk = parse_packets(pcap, max_packets)
    mode = "normal file"
    if cat == tc.NORMAL:
        pk["is_attack"] = np.int8(0)
    else:
        pairs, note = attack_pairs_from_zip(pcap, zip_path)
        if pairs:
            att = pair_keys(pk["src"], pk["dst"]).isin(pairs).to_numpy()
            mode = f"ip pairs from {note}"
            if att.mean() < 0.01:                     # labels did not match this capture
                att, mode = np.ones(len(pk), bool), f"file (pairs matched {100 * att.mean():.2f}% only; {note})"
        else:
            att, mode = np.ones(len(pk), bool), f"file ({note})"
        pk["is_attack"] = att.astype(np.int8)
    return {"pcap": str(pcap), "category": cat, "packets": pk, "label_mode": mode,
            "parse_s": round(time.time() - t0, 1)}


# ---------------------------------------------------------------- CIC features (10 packets per row)
def build_rows(p: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, np.ndarray]:
    """CICIoT2023 rows from packets (already in time order). Returns rows and the row index of every packet."""
    n = len(p)
    if n == 0:
        return pd.DataFrame(columns=features), np.zeros(0, np.int64)
    size = p["size"].to_numpy(np.int64)
    sub = (24 + np.cumsum(16 + size) - 1) // SPLIT_BYTES                 # 10 MB sub-files
    pos = np.arange(n)
    first = np.searchsorted(sub, sub, side="left")
    ts = p["ts"].to_numpy(np.float64)
    iat = np.diff(ts, prepend=ts[0])
    iat[pos == first] = 0.0                                              # IAT restarts in every sub-file
    gid = pd.factorize(sub * 10**9 + (pos - first) // ROW_PACKETS)[0]

    ip_ = (p["is_arp"].to_numpy() == 0).astype(np.int8)
    tcp, udp = p["tcp"].to_numpy(np.int8), p["udp"].to_numpy(np.int8)
    sp, dp, fl, proto = p["sport"].to_numpy(), p["dport"].to_numpy(), p["tflags"].to_numpy(), p["proto"].to_numpy()
    port = lambda x: ((sp == x) | (dp == x)).astype(np.int8)            # noqa: E731
    f = pd.DataFrame({
        "gid": gid, "ts": ts, "size": size, "iat": iat,
        "Header_Length": p["hdr"].to_numpy(np.float64), "Time_To_Live": p["ttl"].to_numpy(np.float64),
        "Protocol Type": proto,
        "fin_flag_number": tcp & ((fl & 0x01) > 0), "syn_flag_number": tcp & ((fl & 0x02) > 0),
        "rst_flag_number": tcp & ((fl & 0x04) > 0), "psh_flag_number": tcp & ((fl & 0x08) > 0),
        "ack_flag_number": tcp & ((fl & 0x10) > 0), "ece_flag_number": tcp & ((fl & 0x40) > 0),
        "cwr_flag_number": tcp & ((fl & 0x80) > 0),
        "HTTP": tcp & port(80), "HTTPS": tcp & port(443), "DNS": udp & port(53), "Telnet": tcp & port(23),
        "SMTP": tcp & port(25), "SSH": tcp & port(22), "IRC": tcp & port(21), "TCP": tcp, "UDP": udp,
        "DHCP": udp & (((sp == 67) & (dp == 68)) | ((sp == 68) & (dp == 67))).astype(np.int8),
        "ARP": 1 - ip_, "ICMP": ip_ & (proto == 1), "IGMP": ip_ & (proto == 2), "IPv": ip_, "LLC": ip_,
        "IAT": iat, "is_attack": p["is_attack"].to_numpy(np.int8),
    })
    g = f.groupby("gid", sort=True)
    rows = g[MEAN_COLS].mean()
    for c, src in COUNT_COLS.items():
        rows[c] = g[src].sum()
    sz = g["size"]
    rows["Tot sum"], rows["Min"], rows["Max"] = sz.sum(), sz.min(), sz.max()
    rows["AVG"] = rows["Tot size"] = sz.mean()
    rows["Std"], rows["Variance"] = sz.std(ddof=1), sz.var(ddof=1)
    rows["Number"] = sz.size()
    span = g["ts"].max() - g["ts"].min()
    with np.errstate(divide="ignore"):
        rows["Rate"] = rows["Number"] / span
    m = f.groupby(["gid", "Protocol Type"]).size().rename("k").reset_index()
    m = m.sort_values(["gid", "k", "Protocol Type"], ascending=[True, False, True]).drop_duplicates("gid")
    rows["Protocol Type"] = m.set_index("gid")["Protocol Type"]
    # same cleaning as training: inf -> NaN -> 0
    rows = rows.replace([np.inf, -np.inf], np.nan).fillna(0)
    out = rows[features].astype(np.float32)
    out["attack_share"] = g["is_attack"].mean().to_numpy()
    out["start_ts"], out["end_ts"] = g["ts"].min().to_numpy(), g["ts"].max().to_numpy()
    src_codes, src_names = pd.factorize(p["src"])
    dom = pd.DataFrame({"gid": gid, "s": src_codes}).groupby(["gid", "s"]).size().rename("k").reset_index()
    dom = dom.sort_values(["gid", "k"], ascending=[True, False]).drop_duplicates("gid").set_index("gid")["s"]
    out["main_src"] = np.asarray(src_names)[dom.reindex(out.index).to_numpy()]
    return out.reset_index(drop=True), gid


# ---------------------------------------------------------------- Suricata
def run_measured(cmd: list[str]) -> tuple[float, float, str]:
    import psutil
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ps, peak = psutil.Process(proc.pid), 0.0
    while proc.poll() is None:
        try:
            peak = max(peak, (ps.memory_info().rss + sum(c.memory_info().rss for c in ps.children(True))) / 2**20)
        except psutil.Error:
            pass
        time.sleep(0.05)
    out = proc.stdout.read() if proc.stdout else ""
    return time.perf_counter() - t0, peak, out


def run_suricata(pcap: Path, out_dir: Path, max_packets: int, log) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    src = pcap
    if max_packets:                                       # --quick: Suricata reads the same first N packets
        src = out_dir / "quick.pcap"
        r = subprocess.run(["tcpdump", "-r", str(pcap), "-w", str(src), "-c", str(max_packets)],
                           capture_output=True, text=True)
        if r.returncode != 0 or not src.exists():
            raise RuntimeError(f"tcpdump could not cut {pcap.name}: {r.stderr[-300:]}")
    cmd = ["suricata", "-S", SURICATA_RULES, "-r", str(src), "-l", str(out_dir), "-k", "none",
           "--runmode", SURICATA_RUNMODE,
           "--set", f"vars.address-groups.HOME_NET={HOME_NET}",
           "--set", f"vars.address-groups.EXTERNAL_NET={EXTERNAL_NET}"]
    for k, v in SURICATA_MEMCAP.items():
        cmd += ["--set", f"{k}={v}"]
    secs, peak, text = run_measured(cmd)
    (out_dir / "stdout.log").write_text(text, encoding="utf-8")
    if max_packets:
        src.unlink(missing_ok=True)                       # temporary cut made by this script
    eve = out_dir / "eve.json"
    slog = out_dir / "suricata.log"
    alltext = text + (slog.read_text(encoding="utf-8", errors="replace") if slog.exists() else "")
    if "initialization failed" in alltext.lower() or not eve.exists():
        raise RuntimeError(f"Suricata failed on {pcap.name}: see {out_dir / 'stdout.log'}\n{text[-600:]}")
    m = re.findall(r"(\d+) packets, (\d+) bytes", alltext)
    pkts = int(m[-1][0]) if m else None
    n_alerts = sum(1 for line in open(eve, encoding="utf-8", errors="replace") if '"event_type":"alert"' in line)
    log.info("   suricata %-50s %6.1f s, peak %5.0f MB, packets %s, alerts %s", pcap.name[:50], secs, peak,
             f"{pkts:,}" if pkts is not None else "?", f"{n_alerts:,}")
    return {"seconds": round(secs, 1), "peak_mb": round(peak, 1), "eve": str(eve), "packets_read": pkts,
            "alerts": n_alerts}


def first_alert_times(eve: Path) -> tuple[dict, dict, dict]:
    """flow key -> first alert time, for ALL alerts and for THREATS; plus signature counts."""
    first_all, first_thr, sigs = {}, {}, {}
    pmap = {"TCP": 6, "UDP": 17, "ICMP": 1}
    with open(eve, encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"event_type":"alert"' not in line:
                continue
            e = json.loads(line)
            ts = pd.Timestamp(e["timestamp"]).timestamp()
            pr = pmap.get(str(e.get("proto", "")).upper(), -1)
            a = f"{e.get('src_ip')}:{e.get('src_port', 0) or 0}"
            b = f"{e.get('dest_ip')}:{e.get('dest_port', 0) or 0}"
            key = f"{pr}|{min(a, b)}|{max(a, b)}"
            sig = e["alert"].get("signature", "")
            sigs[sig] = sigs.get(sig, 0) + 1
            first_all[key] = min(first_all.get(key, ts), ts)
            if not sig.startswith(NOT_THREAT_PREFIXES):
                first_thr[key] = min(first_thr.get(key, ts), ts)
    return first_all, first_thr, sigs


def packet_flow_keys(p: pd.DataFrame) -> pd.Series:
    a = p["src"].astype(str) + ":" + p["sport"].astype(str)
    b = p["dst"].astype(str) + ":" + p["dport"].astype(str)
    lo = np.where(a < b, a, b)
    hi = np.where(a < b, b, a)
    return p["proto"].astype(str) + "|" + pd.Series(lo, index=p.index) + "|" + pd.Series(hi, index=p.index)


# ---------------------------------------------------------------- ML + quarantine
def score_rows(rows: pd.DataFrame, models: dict, log) -> dict:
    out = {}
    for name, (booster, meta) in models.items():
        if len(rows) == 0:
            out[name] = (np.zeros(0), np.zeros(0, int))
            continue
        X = tc.build_X(rows, meta["base_features"], meta["window_features"], meta.get("model", name))
        X = X[meta["inputs"]]
        proba = booster.predict(X)
        normal = meta["categories"].index(tc.NORMAL)
        out[name] = (1.0 - proba[:, normal], proba.argmax(1))
    return out


def quarantine_mask(p: pd.DataFrame, rows: pd.DataFrame, p_attack: np.ndarray, min_hits: int | None = None,
                    duration_s: float | None = None) -> np.ndarray:
    """Packets dropped because their source was quarantined by an earlier ML decision."""
    gap = quarantine_gap(p, rows, p_attack, QUARANTINE_MIN_HITS if min_hits is None else min_hits)
    return gap <= (QUARANTINE_S if duration_s is None else duration_s)          # NaN (never) -> False


def quarantine_gap(p: pd.DataFrame, rows: pd.DataFrame, p_attack: np.ndarray, min_hits: int) -> np.ndarray:
    """Seconds since the packet's source was last quarantined (NaN = never). One sorted join, fast even
    with thousands of spoofed source IPs in a flood."""
    hit = rows.loc[p_attack >= QUARANTINE_P, ["main_src", "end_ts"]]
    if hit.empty:
        return np.full(len(p), np.nan)
    # persistence: a source is quarantined only at a row that is its K-th qualifying row within the window
    hit = hit.astype({"main_src": str}).sort_values(["main_src", "end_ts"]).reset_index(drop=True)
    codes = pd.factorize(hit["main_src"])[0].astype(np.float64)
    t = hit["end_ts"].to_numpy() - hit["end_ts"].min()
    key = codes * (t.max() + QUARANTINE_HIT_WINDOW_S + 1.0) + t        # sorted; sources never overlap
    first = np.searchsorted(key, key - QUARANTINE_HIT_WINDOW_S, side="left")
    hit = hit[(np.arange(len(hit)) - first + 1) >= min_hits]
    if hit.empty:
        return np.full(len(p), np.nan)
    dec = hit.rename(columns={"main_src": "src", "end_ts": "q_ts"}).astype({"src": str})
    dec = dec.sort_values("q_ts").reset_index(drop=True)
    pk = pd.DataFrame({"ts": p["ts"].to_numpy(), "src": p["src"].astype(str).to_numpy(),
                       "i": np.arange(len(p))}).sort_values("ts", kind="stable")
    j = pd.merge_asof(pk, dec, left_on="ts", right_on="q_ts", by="src", direction="backward",
                      allow_exact_matches=False)                         # last decision strictly before
    gap = np.full(len(p), np.nan)
    gap[j["i"].to_numpy()] = (j["ts"] - j["q_ts"]).to_numpy()
    return gap


def quarantine_sweep(inputs: list[dict], log) -> pd.DataFrame:
    """Replay the quarantine rule for every (min hits, quarantine seconds) on the same detector outputs."""
    res = []
    for k in SWEEP_MIN_HITS:
        gaps = [quarantine_gap(it["p"], it["rows"], it["q"], k) for it in inputs]   # one join per k
        for d in SWEEP_QUARANTINE_S:
            a_tot = a_stop = a_q = a_reach = n_tot = n_blk = s_tot = s_blk = before = 0
            first, never = [], 0
            for it, gap in zip(inputs, gaps):
                att, suri = it["att"], it["suri"]
                q = (gap <= d) & ~suri
                stop = suri | q
                a_tot += int(att.sum()); a_stop += int((stop & att).sum()); a_q += int((q & att).sum())
                a_reach += int((~stop & ~it["alert"] & att).sum())
                n_tot += int((~att).sum()); n_blk += int((stop & ~att).sum())
                if it["normal_file"]:
                    s_tot += len(att); s_blk += int(stop.sum())
                if att.any():
                    ts = it["p"]["ts"].to_numpy()
                    sa = stop & att
                    if sa.any():
                        t1 = ts[sa][0]
                        first.append(float(t1 - ts[att][0]))
                        before += int((att & (ts < t1)).sum())
                    else:
                        never += 1
                        before += int(att.sum())
            res.append({"min_hits": k, "quarantine_s": d,
                        "attack_blocked": pct(a_stop, a_tot), "attack_quarantined_by_ml": pct(a_q, a_tot),
                        "attack_reached": pct(a_reach, a_tot),
                        "sensor_normal_wrongly_blocked": pct(s_blk, s_tot),
                        "all_normal_wrongly_blocked": pct(n_blk, n_tot),
                        "median_first_block_s": float(np.median(first)) if first else float("nan"),
                        "attack_files_never_blocked": never, "attack_pkts_before_first_block": before})
            r = res[-1]
            log.info("   sweep hits %d, %4d s: attack blocked %s | sensor normal wrongly blocked %s | "
                     "first block (median) %.2f s | attack files never blocked %d", k, d, fp(r["attack_blocked"]),
                     fp(r["sensor_normal_wrongly_blocked"]), r["median_first_block_s"], never)
    return pd.DataFrame(res)


def sweep_charts(sw: pd.DataFrame, run_dir: Path, log) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": C_GRID, "axes.labelcolor": C_INK2,
                         "xtick.color": C_INK2, "ytick.color": C_INK2, "text.color": C_INK,
                         "figure.facecolor": C_SURFACE, "axes.facecolor": C_SURFACE})
    (run_dir / "charts").mkdir(exist_ok=True)
    cmap = LinearSegmentedColormap.from_list("blue", C_BLUE_RAMP)
    ks, ds = SWEEP_MIN_HITS, SWEEP_QUARANTINE_S
    cur = (QUARANTINE_MIN_HITS, QUARANTINE_S)

    # 02: two heatmaps (each its own scale)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
    for ax, col, title in ((axes[0], "sensor_normal_wrongly_blocked", "Normal sensor packets wrongly blocked (%)\nlower is better"),
                           (axes[1], "attack_blocked", "Attack packets blocked before the resource (%)\nhigher is better")):
        grid = 100 * sw.pivot(index="min_hits", columns="quarantine_s", values=col).loc[ks, ds].to_numpy()
        lo, hi = float(np.nanmin(grid)), float(np.nanmax(grid))      # scale to the data (values can sit
        hi = hi if hi > lo else lo + 1e-6                             # close together, e.g. 33.3-34.1%)
        im = ax.imshow(grid, cmap=cmap, aspect="auto", vmin=lo, vmax=hi)
        for i in range(len(ks)):
            for j in range(len(ds)):
                v = grid[i, j]
                ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=9,
                        color="#ffffff" if (v - lo) > 0.55 * (hi - lo) else C_INK)
        if cur[0] in ks and cur[1] in ds:
            ax.add_patch(plt.Rectangle((ds.index(cur[1]) - 0.5, ks.index(cur[0]) - 0.5), 1, 1, fill=False,
                                       edgecolor=C_INK, linewidth=2))
        ax.set_xticks(range(len(ds)), [f"{d}" for d in ds])
        ax.set_yticks(range(len(ks)), [str(k) for k in ks])
        ax.set_xlabel("Quarantine time (s)")
        ax.set_ylabel("Min hits (rows within 10 s)")
        ax.set_title(title, fontsize=10, color=C_INK, loc="left")
        cb = fig.colorbar(im, ax=ax, shrink=0.85)
        cb.outline.set_visible(False)
    fig.suptitle("Quarantine settings: false blocking vs attack blocking (black box = current setting)",
                 x=0.01, ha="left", fontsize=11, color=C_INK)
    fig.tight_layout()
    fig.savefig(run_dir / "charts" / "02_quarantine_heatmaps.png", dpi=140)
    plt.close(fig)

    # 03: trade-off, one line per min-hits value (quarantine time grows along the line)
    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    for i, k in enumerate(ks):
        d = sw[sw["min_hits"] == k].sort_values("quarantine_s")
        ax.plot(100 * d["sensor_normal_wrongly_blocked"], 100 * d["attack_blocked"], color=C_SERIES[i],
                linewidth=2, marker="o", markersize=7, markeredgecolor=C_SURFACE, markeredgewidth=1.5,
                label=f"{k} hit{'s' if k > 1 else ''}")
        last = d.iloc[-1]
        ax.annotate(f"{k}", (100 * last["sensor_normal_wrongly_blocked"], 100 * last["attack_blocked"]),
                    xytext=(6, 0), textcoords="offset points", fontsize=9, color=C_INK2, va="center")
    c = sw[(sw["min_hits"] == cur[0]) & (sw["quarantine_s"] == cur[1])]
    if not c.empty:
        x, y = 100 * c["sensor_normal_wrongly_blocked"].iloc[0], 100 * c["attack_blocked"].iloc[0]
        ax.scatter([x], [y], s=180, facecolors="none", edgecolors=C_INK, linewidths=2, zorder=5)
        ax.annotate(f"current ({cur[0]} hits, {cur[1]} s)", (x, y), xytext=(10, -14), textcoords="offset points",
                    fontsize=9, color=C_INK)
    ax.set_xlabel("Normal sensor packets wrongly blocked (%)  →  worse")
    ax.set_ylabel("Attack packets blocked before the resource (%)  →  better")
    ax.set_title(f"Trade-off per setting (along each line: quarantine {ds[0]} s → {ds[-1]} s)",
                 fontsize=10, color=C_INK, loc="left")
    ax.grid(True, color=C_GRID, linewidth=0.8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(title="Min hits", frameon=False, loc="lower right")
    fig.tight_layout()
    fig.savefig(run_dir / "charts" / "03_quarantine_tradeoff.png", dpi=140)
    plt.close(fig)

    # 04: reaction speed vs min hits (quarantine time does not change the FIRST block)
    d0 = sw[sw["quarantine_s"] == cur[1] if cur[1] in ds else sw["quarantine_s"] == ds[0]].sort_values("min_hits")
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4))
    for ax, col, lab in ((axes[0], "median_first_block_s", "Median time to first block (s)\n(only attacks that were blocked)"),
                         (axes[1], "attack_pkts_before_first_block", "Attack packets passed before first block\n(never-blocked attacks count fully)"),
                         (axes[2], "attack_files_never_blocked", "Attack files never blocked\n(of 14)")):
        ax.plot(d0["min_hits"], d0[col], color=C_SERIES[0], linewidth=2, marker="o", markersize=7,
                markeredgecolor=C_SURFACE, markeredgewidth=1.5)
        for x, y in zip(d0["min_hits"], d0[col]):
            txt = f"{y:,.2f}" if col.endswith("_s") else f"{int(y):,}"
            ax.annotate(txt, (x, y), xytext=(0, 8), textcoords="offset points", ha="center", fontsize=9, color=C_INK2)
        ax.set_xticks(ks)
        ax.set_xlabel("Min hits (rows within 10 s)")
        ax.set_title(lab, fontsize=10, color=C_INK, loc="left")
        ax.grid(True, axis="y", color=C_GRID, linewidth=0.8)
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_ylim(0, max(float(d0[col].max()) * 1.2, 1))                 # headroom for the labels
    fig.suptitle("How fast the gateway reacts (more hits = more proof = slower first block)", x=0.01, ha="left",
                 fontsize=11, color=C_INK)
    fig.tight_layout()
    fig.savefig(run_dir / "charts" / "04_quarantine_reaction_speed.png", dpi=140)
    plt.close(fig)
    log.info("sweep charts saved: charts/02_quarantine_heatmaps.png, 03_quarantine_tradeoff.png, "
             "04_quarantine_reaction_speed.png")


def pct(a, b) -> float:
    return float(a) / float(b) if b else float("nan")


def fp(v) -> str:
    return "n/a" if v is None or (isinstance(v, float) and np.isnan(v)) else f"{100 * v:.2f}%"


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Suricata (inline) + BAL_MS pipeline on Edge-IIoTset")
    ap.add_argument("--quick", action="store_true", help=f"first {QUICK_PACKETS:,} packets per pcap")
    ap.add_argument("--skip-suricata", action="store_true", help="ML only (no Suricata layer)")
    ap.add_argument("--model-run", type=Path, default=MODEL_RUN)
    ap.add_argument("--data", type=Path, default=EDGE_DIR)
    ap.add_argument("--include", default="", help="only pcaps whose path contains this text")
    ap.add_argument("--calibrate-share", type=float, default=CALIBRATE_SHARE,
                    help="share of every normal pcap (first part, by time) used to learn the site's normal; "
                         "0 = no calibration (old test)")
    ap.add_argument("--pipeline-model", default=PIPELINE_MODEL, choices=["BAL_MS_cal", "FLAT_cal"])
    ap.add_argument("--no-sweep", action="store_true", help="skip the quarantine settings sweep (charts 02-04)")
    ap.add_argument("--replot", type=Path, default=None,
                    help="only redraw charts 02-04 from <run dir>/quarantine_sweep.csv (no new run)")
    args = ap.parse_args()
    if args.replot:
        import logging
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        sweep_charts(pd.read_csv(args.replot / "quarantine_sweep.csv"), args.replot, logging.getLogger("replot"))
        return 0
    global MODELS

    random.seed(SEED)
    np.random.seed(SEED)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    tc.SCRIPT_NAME = SCRIPT_NAME
    log = tc.setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    try:
        env = tc.log_environment(log)
        if not args.skip_suricata and not shutil.which("suricata"):
            raise SystemExit("suricata command not found (or use --skip-suricata)")
        if args.quick and not args.skip_suricata and not shutil.which("tcpdump"):
            raise SystemExit("--quick needs tcpdump to cut the pcaps for Suricata")
        max_packets = QUICK_PACKETS if args.quick else 0
        pcaps = sorted(p for p in args.data.rglob("*") if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng")
                       and args.include.lower() in str(p).lower())
        if not pcaps:
            raise SystemExit(f"no pcaps under {args.data}")

        import lightgbm as lgb
        models = {}
        for name in MODELS:
            mdir = args.model_run / "models" / name
            meta = json.loads((mdir / "features.json").read_text(encoding="utf-8"))
            models[name] = (lgb.Booster(model_file=str(mdir / "model.txt")), meta)
        features = models[MODELS[0]][1]["base_features"]
        model_cats = models[MODELS[0]][1]["categories"]

        config = {"script": SCRIPT_NAME, "data": str(args.data), "pcaps": [str(p) for p in pcaps],
                  "model_run": str(args.model_run), "models": MODELS, "quick": args.quick,
                  "max_packets": max_packets, "skip_suricata": args.skip_suricata, "row_packets": ROW_PACKETS,
                  "split_bytes": SPLIT_BYTES, "row_attack_share": ROW_ATTACK_SHARE, "alert_p": ALERT_P,
                  "quarantine_p": QUARANTINE_P, "quarantine_s": QUARANTINE_S, "suricata_rules": SURICATA_RULES,
                  "home_net": HOME_NET, "external_net": EXTERNAL_NET, "not_threat_prefixes": NOT_THREAT_PREFIXES,
                  "edge_category": EDGE_CATEGORY, "environment": env}
        tc.write_json(run_dir / "config.json", config)
        log.info("%d pcaps | models %s from %s | quick %s | Suricata %s", len(pcaps), MODELS, args.model_run.name,
                 args.quick, "off" if args.skip_suricata else "on")

        # 1) Suricata on every pcap (layer 1)
        suri: dict = {}
        if not args.skip_suricata:
            log.info("1) Suricata on %d pcaps (%d at a time)", len(pcaps), SURICATA_JOBS)
            with ThreadPoolExecutor(SURICATA_JOBS) as pool:
                futs = {p: pool.submit(run_suricata, p, run_dir / "suricata" / norm(p.stem)[:60], max_packets, log)
                        for p in pcaps}
                suri = {p: f.result() for p, f in futs.items()}

        # 2) parse + label packets (parallel)
        log.info("2) reading packets + labels (%d at a time)", PARSE_JOBS)
        with ProcessPoolExecutor(min(PARSE_JOBS, len(pcaps))) as pool:
            loaded = list(pool.map(load_file, [(p, max_packets, EDGE_ZIP) for p in pcaps]))

        # 2b) site calibration: learn the local normal from the first part of every NORMAL pcap
        ae, cinfo = None, {}
        if args.calibrate_share > 0:
            import site_calibration as sc
            log.info("2b) calibration on the first %.0f%% of every normal pcap (no attack labels used)",
                     100 * args.calibrate_share)
            loc_tr, loc_va = [], []
            for item in loaded:
                if item["category"] != tc.NORMAL or len(item["packets"]) == 0:
                    continue
                p = item["packets"].sort_values("ts", kind="stable").reset_index(drop=True)
                cut = int(args.calibrate_share * len(p))
                cal_rows, _ = build_rows(p.iloc[:cut].reset_index(drop=True), features)
                k = int((1 - CALIBRATE_VAL_SHARE) * len(cal_rows))
                loc_tr.append(cal_rows.iloc[:k].reset_index(drop=True))
                loc_va.append(cal_rows.iloc[k:].reset_index(drop=True))
                item["packets"] = p.iloc[cut:].reset_index(drop=True)          # test = the rest
                item["calibration_packets"] = cut
                log.info("   %-34s learning %s packets -> %s rows | test %s packets", Path(item["pcap"]).name,
                         f"{cut:,}", f"{len(cal_rows):,}", f"{len(item['packets']):,}")
            if not loc_tr:
                raise SystemExit("calibration: no normal pcaps found")
            cal_models, ae, cinfo = sc.calibrate(loc_tr, loc_va, args.model_run, run_dir, log)
            base_bal = models[MODELS[0]]
            first = {args.pipeline_model: cal_models[args.pipeline_model]}   # pipeline model first
            models = {**first, **cal_models, f"{MODELS[0]}_base": base_bal}  # + base model for comparison
            MODELS = list(models)
            config.update(calibrate_share=args.calibrate_share, calibration=cinfo, models=MODELS)
            tc.write_json(run_dir / "config.json", config)

        # 3) per file: inline Suricata -> features -> ML -> quarantine
        log.info("3) pipeline per file")
        per_file, all_rows, sig_total, sweep_inputs = [], [], {}, []
        tot = {k: 0 for k in ("att", "norm", "att_suri_all", "norm_suri_all", "att_suri_thr", "norm_suri_thr",
                              "att_blk_suri", "att_blk_q", "att_alert", "att_reached", "norm_blk_suri",
                              "norm_blk_q", "norm_alert")}
        for m in MODELS + ["AE", "MLAE"]:
            tot[f"att_ml_{m}"] = tot[f"norm_ml_{m}"] = 0
        for item in loaded:
            pcap, cat, p = Path(item["pcap"]), item["category"], item["packets"]
            if len(p) == 0:
                log.warning("   %s: no IPv4/ARP packets", pcap.name)
                continue
            p = p.sort_values("ts", kind="stable").reset_index(drop=True)
            log.info("   working on %s (%s packets) ...", pcap.name, f"{len(p):,}")
            att = p["is_attack"].to_numpy().astype(bool)
            # Suricata masks (drop from the first alert on that flow)
            if pcap in suri:
                fa, ft, sigs = first_alert_times(Path(suri[pcap]["eve"]))
                for s, c in sigs.items():
                    sig_total[s] = sig_total.get(s, 0) + c
                keys = packet_flow_keys(p)
                ts = p["ts"].to_numpy()
                t_all = keys.map(fa).astype(float).fillna(np.inf).to_numpy()
                t_thr = keys.map(ft).astype(float).fillna(np.inf).to_numpy()
                suri_all, suri_thr = ts >= t_all - 1e-6, ts >= t_thr - 1e-6
            else:
                suri_all = suri_thr = np.zeros(len(p), bool)

            # ML alone: all packets
            rows_a, gid_a = build_rows(p, features)
            sc_a = score_rows(rows_a, models, log)
            # inline: only packets Suricata let through
            keep = ~suri_thr
            pb = p[keep].reset_index(drop=True)
            rows_b, gid_b = build_rows(pb, features)
            sc_b = score_rows(rows_b, models, log)
            pa_b = sc_b[MODELS[0]][0]
            row_alert_b = pa_b >= ALERT_P
            ae_a = ae.score(rows_a) > ae.threshold if ae is not None else np.zeros(len(rows_a), bool)
            q_score = pa_b
            if ae is not None:
                ae_b = ae.score(rows_b) > ae.threshold
                row_alert_b = row_alert_b | ae_b                               # AE anomaly = alert too
                if QUARANTINE_NEEDS_AE:
                    q_score = np.where(ae_b, pa_b, 0.0)                        # quarantine only if both agree
            alert_b_pkt = np.zeros(len(p), bool)
            alert_b_pkt[np.flatnonzero(keep)] = row_alert_b[gid_b] if len(pb) else False
            q = quarantine_mask(p, rows_b, q_score) & ~suri_thr
            if not args.no_sweep:
                sweep_inputs.append({"p": p[["ts", "src"]], "att": att, "suri": suri_thr, "alert": alert_b_pkt,
                                     "rows": rows_b[["main_src", "end_ts"]], "q": q_score,
                                     "normal_file": cat == tc.NORMAL})

            blk_suri, blk_q = suri_thr, q & ~suri_thr
            alert_only = alert_b_pkt & ~blk_suri & ~blk_q
            reached = ~blk_suri & ~blk_q & ~alert_b_pkt
            na, nn = int(att.sum()), int((~att).sum())
            r = {"pcap": pcap.name, "category": cat, "label_mode": item["label_mode"], "packets": len(p),
                 "attack_packets": na, "rows": len(rows_a), "parse_s": item["parse_s"],
                 "suricata_s": suri.get(pcap, {}).get("seconds"), "suricata_peak_mb": suri.get(pcap, {}).get("peak_mb"),
                 "suri_all_attack": pct((suri_all & att).sum(), na), "suri_thr_attack": pct((suri_thr & att).sum(), na),
                 "blocked_suricata": pct((blk_suri & att).sum(), na), "quarantined_ml": pct((blk_q & att).sum(), na),
                 "alert_only_ml": pct((alert_only & att).sum(), na), "reached": pct((reached & att).sum(), na),
                 "normal_wrongly_blocked": pct(((blk_suri | blk_q) & ~att).sum(), nn),
                 "normal_alerted": pct((alert_b_pkt & ~att & ~blk_suri & ~blk_q).sum(), nn)}
            if ae is not None:
                rr0 = rows_a["attack_share"].to_numpy() >= ROW_ATTACK_SHARE
                sel0 = rr0 if rr0.any() else np.ones(len(rows_a), bool)
                r["ae_rows_flagged"] = float(ae_a[sel0].mean()) if sel0.any() else float("nan")
                for nm, flag in (("AE", ae_a), ("MLAE", (sc_a[MODELS[0]][0] >= ALERT_P) | ae_a)):
                    pk_flag = flag[gid_a]
                    tot[f"att_ml_{nm}"] += int((pk_flag & att).sum())
                    tot[f"norm_ml_{nm}"] += int((pk_flag & ~att).sum())
            for m in MODELS:
                pa_a, pred_a = sc_a[m]
                pkt_alert = (pa_a >= ALERT_P)[gid_a]
                r[f"ml_{m}_attack_pkts"] = pct((pkt_alert & att).sum(), na)
                r[f"ml_{m}_normal_pkts"] = pct((pkt_alert & ~att).sum(), nn)
                tot[f"att_ml_{m}"] += int((pkt_alert & att).sum())
                tot[f"norm_ml_{m}"] += int((pkt_alert & ~att).sum())
                rr = rows_a["attack_share"].to_numpy() >= ROW_ATTACK_SHARE
                r[f"ml_{m}_attack_rows_alerted"] = pct((pa_a[rr] >= ALERT_P).sum(), rr.sum())
                if cat in model_cats and rr.any():
                    r[f"ml_{m}_right_category"] = pct((pred_a[rr] == model_cats.index(cat)).sum(), rr.sum())
                sel = rr if rr.any() else np.ones(len(pred_a), bool)      # normal files: all rows
                if sel.any():
                    names = pd.Series(np.asarray(model_cats)[pred_a[sel]]).value_counts(normalize=True).head(3)
                    r[f"ml_{m}_predicted_as"] = ", ".join(f"{k} {100 * v:.0f}%" for k, v in names.items())
            # time to first block (attack packets that passed before)
            if na:
                ts = p["ts"].to_numpy()
                stop = (blk_suri | blk_q) & att
                t0 = ts[att][0]
                if stop.any():
                    t1 = ts[stop][0]
                    r["first_block_s"] = round(float(t1 - t0), 2)
                    r["attack_pkts_before_block"] = int((att & (ts < t1)).sum())
                    r["first_block_by"] = "Suricata" if blk_suri[np.flatnonzero(stop)[0]] else "ML quarantine"
                else:
                    r["first_block_s"], r["attack_pkts_before_block"], r["first_block_by"] = None, na, "never"
            per_file.append(r)
            for k, v in (("att", na), ("norm", nn), ("att_suri_all", (suri_all & att).sum()),
                         ("norm_suri_all", (suri_all & ~att).sum()), ("att_suri_thr", (suri_thr & att).sum()),
                         ("norm_suri_thr", (suri_thr & ~att).sum()), ("att_blk_suri", (blk_suri & att).sum()),
                         ("att_blk_q", (blk_q & att).sum()), ("att_alert", (alert_only & att).sum()),
                         ("att_reached", (reached & att).sum()), ("norm_blk_suri", (blk_suri & ~att).sum()),
                         ("norm_blk_q", (blk_q & ~att).sum()), ("norm_alert", (alert_only & ~att).sum())):
                tot[k] += int(v)
            keep_cols = rows_a.copy()                                    # features + meta (for the shift check)
            keep_cols["pcap"], keep_cols["category"] = pcap.name, cat
            for m in MODELS:
                keep_cols[f"p_attack_{m}"] = sc_a[m][0]
                keep_cols[f"pred_{m}"] = np.asarray(model_cats)[sc_a[m][1]] if len(rows_a) else []
            keep_cols["ae_flag"] = ae_a
            all_rows.append(keep_cols)
            log.info("   %-48s %-22s %9s pkts (%5.1f%% attack) | Suricata blocked %s | ML quarantined %s | "
                     "alert only %s | reached %s | normal wrongly blocked %s | label: %s",
                     pcap.name[:48], cat[:22], f"{len(p):,}", 100 * na / max(len(p), 1), fp(r["blocked_suricata"]),
                     fp(r["quarantined_ml"]), fp(r["alert_only_ml"]), fp(r["reached"]),
                     fp(r["normal_wrongly_blocked"]), item["label_mode"][:40])

        # 4) row-level ML metrics (all files)
        rows = pd.concat(all_rows, ignore_index=True)
        rows.to_parquet(run_dir / "rows.parquet", index=False)
        is_att = rows["attack_share"].to_numpy() >= ROW_ATTACK_SHARE
        ml_rows = {}
        for m in MODELS:
            al = rows[f"p_attack_{m}"].to_numpy() >= ALERT_P
            tp, fp_, fn = int((al & is_att).sum()), int((al & ~is_att).sum()), int((~al & is_att).sum())
            det, far, prec = pct(tp, tp + fn), pct(fp_, (~is_att).sum()), pct(tp, tp + fp_)
            known = is_att & rows["category"].isin(model_cats).to_numpy()
            ml_rows[m] = {"detection_rate": det, "false_alarm_rate": far, "precision": prec,
                          "f1": 2 * prec * det / (prec + det) if prec + det else 0.0,
                          "right_category_known_attacks": pct((rows[f"pred_{m}"].to_numpy()[known]
                                                               == rows["category"].to_numpy()[known]).sum(), known.sum()),
                          "attack_rows": int(is_att.sum()), "normal_rows": int((~is_att).sum())}
            log.info("ML ALONE %-12s rows: detection %s | false alarms %s | precision %s | F1 %.4f | right category %s",
                     m, fp(det), fp(far), fp(prec), ml_rows[m]["f1"], fp(ml_rows[m]["right_category_known_attacks"]))
        if ae is not None:
            for nm, al in (("AUTOENCODER", rows["ae_flag"].to_numpy()),
                           (f"{MODELS[0]} + AE", (rows[f"p_attack_{MODELS[0]}"].to_numpy() >= ALERT_P)
                            | rows["ae_flag"].to_numpy())):
                tp, fp_, fn = int((al & is_att).sum()), int((al & ~is_att).sum()), int((~al & is_att).sum())
                det, far, prec = pct(tp, tp + fn), pct(fp_, (~is_att).sum()), pct(tp, tp + fp_)
                ml_rows[nm] = {"detection_rate": det, "false_alarm_rate": far, "precision": prec,
                               "f1": 2 * prec * det / (prec + det) if prec + det else 0.0,
                               "right_category_known_attacks": float("nan"),
                               "attack_rows": int(is_att.sum()), "normal_rows": int((~is_att).sum())}
                log.info("ML ALONE %-12s rows: detection %s | false alarms %s | precision %s | F1 %.4f",
                         nm, fp(det), fp(far), fp(prec), ml_rows[nm]["f1"])

        A, N = tot["att"], tot["norm"]
        pkt = {"SURICATA_ALL alone": (pct(tot["att_suri_all"], A), pct(tot["norm_suri_all"], N)),
               "SURICATA_THREATS alone": (pct(tot["att_suri_thr"], A), pct(tot["norm_suri_thr"], N))}
        for m in MODELS:
            pkt[f"{m} alone (alert)"] = (pct(tot[f"att_ml_{m}"], A), pct(tot[f"norm_ml_{m}"], N))
        if ae is not None:
            pkt["AUTOENCODER alone"] = (pct(tot["att_ml_AE"], A), pct(tot["norm_ml_AE"], N))
            pkt[f"{MODELS[0]} + AE (no Suricata)"] = (pct(tot["att_ml_MLAE"], A), pct(tot["norm_ml_MLAE"], N))
        pipeline = {"blocked_by_suricata": pct(tot["att_blk_suri"], A), "quarantined_by_ml": pct(tot["att_blk_q"], A),
                    "alert_only_ml": pct(tot["att_alert"], A), "reached_resource": pct(tot["att_reached"], A),
                    "stopped_total": pct(tot["att_blk_suri"] + tot["att_blk_q"], A),
                    "detected_total": pct(tot["att_blk_suri"] + tot["att_blk_q"] + tot["att_alert"], A),
                    "normal_wrongly_blocked": pct(tot["norm_blk_suri"] + tot["norm_blk_q"], N),
                    "normal_alerted_only": pct(tot["norm_alert"], N)}
        pkt[f"COMBINED (Suricata inline + {MODELS[0]}{' + AE' if ae is not None else ''})"] = (pipeline["detected_total"],
                                                     pct(tot["norm_blk_suri"] + tot["norm_blk_q"] + tot["norm_alert"], N))
        for k, (d, f_) in pkt.items():
            log.info("PACKETS %-38s attack packets caught %s | normal packets flagged %s", k, fp(d), fp(f_))
        log.info("PIPELINE attack packets: Suricata blocked %s | ML quarantined %s | ML alert only %s | REACHED %s | "
                 "normal wrongly blocked %s", fp(pipeline["blocked_by_suricata"]), fp(pipeline["quarantined_by_ml"]),
                 fp(pipeline["alert_only_ml"]), fp(pipeline["reached_resource"]),
                 fp(pipeline["normal_wrongly_blocked"]))

        sweep = pd.DataFrame()
        if sweep_inputs:
            log.info("quarantine sweep: min hits %s x quarantine seconds %s", SWEEP_MIN_HITS, SWEEP_QUARANTINE_S)
            sweep = quarantine_sweep(sweep_inputs, log)
            sweep.to_csv(run_dir / "quarantine_sweep.csv", index=False)
            sweep_charts(sweep, run_dir, log)
            del sweep_inputs
        mixed_sum, mixed_pf = mixed_test(rows, models, ae, model_cats, log)
        mixed_pf.to_csv(run_dir / "mixed_test_per_attack.csv", index=False)
        shift = feature_shift(rows, features, log)
        shift.to_csv(run_dir / "feature_shift.csv", index=False)
        pf = pd.DataFrame(per_file)
        pf.to_csv(run_dir / "per_file.csv", index=False)
        top_sigs = sorted(sig_total.items(), key=lambda kv: -kv[1])[:15]
        make_chart(pf, run_dir, log)
        write_report(run_dir, pf, ml_rows, pkt, pipeline, top_sigs, tot, args, model_cats, shift, cinfo,
                     mixed_sum, mixed_pf, sweep)
        out.update(status="ok", ml_rows=ml_rows, mixed_test=mixed_sum,
                   quarantine_sweep=sweep.to_dict(orient="records"), packets={k: {"attack_caught": d, "normal_flagged": f_}
                                                          for k, (d, f_) in pkt.items()},
                   pipeline=pipeline, totals=tot, per_file=per_file, top_signatures=top_sigs,
                   report=str(run_dir / "REPORT.md"))
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    tc.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("report: %s", out["report"])
        log.info("FINISHED OK (%.1f min)", out["time_taken_s"] / 60)
        return 0
    log.error("FINISHED WITH ERROR")
    return 1


# ---------------------------------------------------------------- mixed test (attacks hidden in normal)
def mixed_test(rows: pd.DataFrame, models: dict, ae, model_cats: list[str], log) -> tuple[dict, pd.DataFrame]:
    """Edge attack rows inserted INTO the normal sensor test streams (bursts 200-2000 rows + solo 1-5 rows),
    like the training streams. Windows then see attacks among real site traffic: the realistic case."""
    rng = np.random.default_rng(SEED + 7)
    normal = {f: d for f, d in rows[rows["category"] == tc.NORMAL].groupby("pcap", sort=True)}
    attack_rows = rows[(rows["category"] != tc.NORMAL) & (rows["attack_share"] >= ROW_ATTACK_SHARE)]
    attacks = {f: d.iloc[:MIX_ATTACK_ROWS_PER_FILE] for f, d in attack_rows.groupby("pcap", sort=True)}
    if not normal or not attacks:
        return {}, pd.DataFrame()
    names = list(models) + (["AUTOENCODER", f"{list(models)[0]} + AE"] if ae is not None else [])
    acc = {n: [] for n in names}
    meta = []
    for i, (nf, nd) in enumerate(normal.items()):
        parts, cc = {"N:" + nf: [nd.assign(cls="N:" + nf)]}, {"N:" + nf: tc.NORMAL}
        for af, ad in attacks.items():
            idx = np.array_split(np.arange(len(ad)), len(normal))[i]
            if len(idx):
                parts["A:" + af] = [ad.iloc[idx].assign(cls="A:" + af)]
                cc["A:" + af] = ad["category"].iloc[0]
        st = tc.build_stream(parts, cc, rng, tc.SOLO_SHARE)
        ctx = tc.context(st)
        sc = score_rows(st, models, log)
        ae_flag = ae.score(st) > ae.threshold if ae is not None else None
        for n in models:
            acc[n].append((sc[n][0] >= ALERT_P, sc[n][1]))
        if ae is not None:
            acc["AUTOENCODER"].append((ae_flag, None))
            acc[names[len(models) + 1]].append(((sc[list(models)[0]][0] >= ALERT_P) | ae_flag, sc[list(models)[0]][1]))
        meta.append(pd.DataFrame({"cls": st["cls"].to_numpy(), "category": st["category"].to_numpy(),
                                  "hidden": ctx["hidden"], "start": ctx["start"], "spill": ctx["spill"],
                                  "attack": ctx["attack"]}))
    m = pd.concat(meta, ignore_index=True)
    att, cat = m["attack"].to_numpy(), m["category"].to_numpy()
    known = att & np.isin(cat, model_cats)
    summary, per = {}, []
    for n in names:
        alert = np.concatenate([a for a, _ in acc[n]])
        pred = None if acc[n][0][1] is None else np.concatenate([p for _, p in acc[n]])
        s = {"detection_rate": pct((alert & att).sum(), att.sum()),
             "false_alarm_rate": pct((alert & ~att).sum(), (~att).sum()),
             "hidden_detection": pct((alert & m["hidden"].to_numpy()).sum(), m["hidden"].sum()),
             "attack_start_detection": pct((alert & m["start"].to_numpy()).sum(), m["start"].sum()),
             "spill_false_alarm_rate": pct((alert & m["spill"].to_numpy()).sum(), m["spill"].sum()),
             "right_category_known": (pct((np.asarray(model_cats)[pred][known] == cat[known]).sum(), known.sum())
                                      if pred is not None else float("nan"))}
        prec = pct((alert & att).sum(), alert.sum())
        s["f1"] = 2 * prec * s["detection_rate"] / (prec + s["detection_rate"]) if prec + s["detection_rate"] else 0.0
        summary[n] = s
        log.info("MIXED %-18s detection %s | false alarms %s | hidden %s | start %s | spill FA %s | right cat. %s",
                 n, fp(s["detection_rate"]), fp(s["false_alarm_rate"]), fp(s["hidden_detection"]),
                 fp(s["attack_start_detection"]), fp(s["spill_false_alarm_rate"]), fp(s["right_category_known"]))
        for c in sorted(set(m.loc[att, "cls"])):
            sel = (m["cls"] == c).to_numpy()
            per.append({"model": n, "attack_pcap": c[2:], "category": cat[sel][0], "rows": int(sel.sum()),
                        "detected": float(alert[sel].mean()),
                        "right_category": (float((np.asarray(model_cats)[pred[sel]] == cat[sel]).mean())
                                           if pred is not None and cat[sel][0] in model_cats else float("nan"))})
    summary["_rows"] = {"attack": int(att.sum()), "normal": int((~att).sum()), "hidden": int(m["hidden"].sum())}
    return summary, pd.DataFrame(per)


# ---------------------------------------------------------------- feature shift check
def feature_shift(rows: pd.DataFrame, features: list[str], log) -> pd.DataFrame:
    """Edge-IIoTset NORMAL rows vs CICIoT2023 Benign training rows: where do they differ?"""
    files = sorted(p for p in tc.DATA_DIR.rglob("*.csv") if "benign" in p.parent.name.lower())
    if not files:
        log.warning("feature shift: no CICIoT2023 Benign CSVs under %s", tc.DATA_DIR)
        return pd.DataFrame()
    per = max(1, SHIFT_SAMPLE_ROWS // len(files))
    cic = pd.concat([pd.read_csv(f, nrows=per, dtype=np.float32) for f in files], ignore_index=True)
    cic.columns = [c.strip() for c in cic.columns]
    cic = cic.replace([np.inf, -np.inf], np.nan).fillna(0)
    edge = rows.loc[rows["category"] == tc.NORMAL, features]
    out = []
    for f in features:
        c, e = cic[f].to_numpy(np.float64), edge[f].to_numpy(np.float64)
        lo, hi = np.percentile(c, 1), np.percentile(c, 99)
        out.append({"feature": f, "cic_benign_median": float(np.median(c)), "edge_normal_median": float(np.median(e)),
                    "cic_p1": float(lo), "cic_p99": float(hi),
                    "edge_outside_cic_1_99": float(((e < lo) | (e > hi)).mean()) if len(e) else float("nan")})
    out = pd.DataFrame(out).sort_values("edge_outside_cic_1_99", ascending=False)
    log.info("feature shift (Edge normal rows outside the CICIoT2023 Benign 1-99%% range), top 10:")
    for _, r in out.head(10).iterrows():
        log.info("   %-16s outside %6.1f%% | CIC benign median %12.4g | Edge normal median %12.4g", r["feature"],
                 100 * r["edge_outside_cic_1_99"], r["cic_benign_median"], r["edge_normal_median"])
    return out


# ---------------------------------------------------------------- report
def make_chart(pf: pd.DataFrame, run_dir: Path, log) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    d = pf[pf["attack_packets"] > 0].sort_values("reached")
    if d.empty:
        return
    parts = [("blocked_suricata", "Blocked by Suricata", "#1f6f8b"), ("quarantined_ml", "Quarantined by ML", "#59a14f"),
             ("alert_only_ml", "ML alert only", "#e0b040"), ("reached", "Reached resource", "#c8553d")]
    fig, ax = plt.subplots(figsize=(11, 0.45 * len(d) + 1.5))
    left = np.zeros(len(d))
    for col, label, color in parts:
        v = 100 * d[col].fillna(0).to_numpy()
        ax.barh(d["pcap"].str.slice(0, 45), v, left=left, label=label, color=color)
        left += v
    ax.set_xlabel("% of attack packets")
    ax.set_title("Edge-IIoTset: what happened to the attack packets (Suricata inline + BAL_MS)")
    ax.legend(frameon=False, ncol=4, loc="lower center", bbox_to_anchor=(0.5, 1.02))
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    (run_dir / "charts").mkdir(exist_ok=True)
    fig.savefig(run_dir / "charts" / "01_pipeline_per_attack.png", dpi=130)
    plt.close(fig)
    log.info("chart saved: %s", run_dir / "charts" / "01_pipeline_per_attack.png")


def write_report(run_dir, pf, ml_rows, pkt, pipeline, top_sigs, tot, args, model_cats, shift, cinfo,
                 mixed_sum=None, mixed_pf=None, sweep=None) -> None:
    m0 = MODELS[0]
    cal = ""
    if cinfo:
        cal = (f"**Site calibration (enterprise test):** the first {100 * args.calibrate_share:.0f}% (by time) of every "
               f"NORMAL pcap was the learning period ({cinfo['local_train_rows']:,} + {cinfo['local_val_rows']:,} "
               "rows). It was used only as 'Normal' (no attack labels from Edge-IIoTset). The attack knowledge is "
               "still CICIoT2023. All results below use ONLY the rest of the normal traffic + all attack pcaps. "
               f"`{m0}` = calibrated model, `*_base` = the model without calibration (for comparison). "
               f"Autoencoder threshold {cinfo['autoencoder']['threshold']:.4f}. Calibration took "
               f"{cinfo['seconds'] / 60:.1f} min. Details: calibration.json.\n\n")
    L = ["# Edge-IIoTset: Suricata (inline) + BAL_MS pipeline", "", cal +
         f"Test data never seen in training. Models from `{args.model_run.name}`. "
         f"{'QUICK run: first ' + format(QUICK_PACKETS, ',') + ' packets per pcap. ' if args.quick else ''}"
         f"Attack packets: {tot['att']:,}; normal packets: {tot['norm']:,}.", "",
         "## 1. The pipeline (attack packets)", "",
         "| Blocked by Suricata | Quarantined by ML | ML alert only | **Reached the resource** | "
         "Normal packets wrongly blocked | Normal packets alerted only |", "|---|---|---|---|---|---|",
         f"| {fp(pipeline['blocked_by_suricata'])} | {fp(pipeline['quarantined_by_ml'])} | "
         f"{fp(pipeline['alert_only_ml'])} | **{fp(pipeline['reached_resource'])}** | "
         f"{fp(pipeline['normal_wrongly_blocked'])} | {fp(pipeline['normal_alerted_only'])} |", "",
         f"Blocked = dropped before the resource. Quarantine = ML P(attack) ≥ {QUARANTINE_P}"
         f"{' AND autoencoder anomaly' if QUARANTINE_NEEDS_AE and cinfo else ''}, on at least "
         f"{QUARANTINE_MIN_HITS} rows of the same source within {QUARANTINE_HIT_WINDOW_S} s → that source "
         f"is dropped for {QUARANTINE_S} s. Alert only = ML P(attack) ≥ {ALERT_P}, trust score lowered, no block.", "",
         "## 2. Each detector alone vs combined (packets)", "",
         "| Detector | Attack packets caught | Normal packets flagged |", "|---|---|---|"]
    for k, (d, f_) in pkt.items():
        L.append(f"| {k} | {fp(d)} | {fp(f_)} |")
    L += ["", "## 3. ML alone (rows of 10 packets)", "",
          "| Model | Detection | False alarms | Precision | F1 | Right category (trained attack types) |",
          "|---|---|---|---|---|---|"]
    for m, r in ml_rows.items():
        L.append(f"| {m} | {fp(r['detection_rate'])} | {fp(r['false_alarm_rate'])} | {fp(r['precision'])} | "
                 f"{r['f1']:.4f} | {fp(r['right_category_known_attacks'])} |")
    if sweep is not None and not sweep.empty:
        L += ["", "## 3a. Quarantine settings sweep (same detector outputs, only the rule changes)", "",
              f"Min hits = qualifying rows from one source within {QUARANTINE_HIT_WINDOW_S} s before it is quarantined. "
              f"Current setting: {QUARANTINE_MIN_HITS} hits, {QUARANTINE_S} s. 'Sensor normal' = packets of the "
              "normal-traffic pcaps (test part).", "",
              "| Min hits | Quarantine s | Attack blocked | ML quarantined | Attack reached | Sensor normal wrongly "
              "blocked | All normal wrongly blocked | Median first block | Attack files never blocked |",
              "|---|---|---|---|---|---|---|---|---|"]
        for _, s in sweep.iterrows():
            mark = " **(current)**" if (s["min_hits"], s["quarantine_s"]) == (QUARANTINE_MIN_HITS, QUARANTINE_S) else ""
            L.append(f"| {int(s['min_hits'])}{mark} | {int(s['quarantine_s'])} | {fp(s['attack_blocked'])} | "
                     f"{fp(s['attack_quarantined_by_ml'])} | {fp(s['attack_reached'])} | "
                     f"{fp(s['sensor_normal_wrongly_blocked'])} | {fp(s['all_normal_wrongly_blocked'])} | "
                     f"{s['median_first_block_s']:.2f} s | {int(s['attack_files_never_blocked'])} |")
        L += ["", "![heatmaps](charts/02_quarantine_heatmaps.png)", "",
              "![trade-off](charts/03_quarantine_tradeoff.png)", "",
              "![reaction speed](charts/04_quarantine_reaction_speed.png)"]
    if mixed_sum:
        r0 = mixed_sum["_rows"]
        L += ["", "## 3b. Mixed test: Edge attacks HIDDEN inside the normal sensor traffic (realistic)", "",
              f"Edge attack rows inserted into the normal test streams as bursts (200–2000 rows) and solo attacks "
              f"(1–5 rows). Attack rows {r0['attack']:,}, normal rows {r0['normal']:,}, hidden attack rows "
              f"{r0['hidden']:,}.", "",
              "| Model | Detection | False alarms | Hidden attacks | Attack start | Spill-over false alarms | F1 | "
              "Right category |", "|---|---|---|---|---|---|---|---|"]
        for n, s in mixed_sum.items():
            if n.startswith("_"):
                continue
            L.append(f"| {n} | {fp(s['detection_rate'])} | {fp(s['false_alarm_rate'])} | {fp(s['hidden_detection'])} | "
                     f"{fp(s['attack_start_detection'])} | {fp(s['spill_false_alarm_rate'])} | {s['f1']:.4f} | "
                     f"{fp(s['right_category_known'])} |")
        if mixed_pf is not None and not mixed_pf.empty:
            piv = mixed_pf.pivot_table(index=["attack_pcap", "category"], columns="model", values="detected")
            L += ["", "Detected share per attack (mixed test):", "",
                  "| Attack pcap | Category | " + " | ".join(piv.columns) + " |",
                  "|---|---|" + "---|" * len(piv.columns)]
            for (a, c), row in piv.iterrows():
                L.append(f"| {a[:40]} | {c} | " + " | ".join(fp(v) for v in row.to_numpy()) + " |")
    L += ["", "## 4. Per attack file", "",
          "| pcap | Category | Attack pkts | Suricata blocked | ML quarantined | Alert only | Reached | "
          f"{m0} rows alerted | {m0} right cat. | {m0} called it | First block | Attack pkts before block | By |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for _, r in pf[pf["attack_packets"] > 0].iterrows():
        L.append(f"| {r['pcap'][:40]} | {r['category']} | {r['attack_packets']:,} | {fp(r['blocked_suricata'])} | "
                 f"{fp(r['quarantined_ml'])} | {fp(r['alert_only_ml'])} | {fp(r['reached'])} | "
                 f"{fp(r.get(f'ml_{m0}_attack_rows_alerted'))} | {fp(r.get(f'ml_{m0}_right_category'))} | "
                 f"{r.get(f'ml_{m0}_predicted_as', '') if isinstance(r.get(f'ml_{m0}_predicted_as'), str) else ''} | "
                 f"{'' if pd.isna(r.get('first_block_s')) else str(r.get('first_block_s')) + ' s'} | "
                 f"{r.get('attack_pkts_before_block', '')} | {r.get('first_block_by', '')} |")
    L += ["", "## 5. Normal traffic files", "",
          f"| pcap | Packets | Wrongly blocked | Alerted only | {m0} called it |", "|---|---|---|---|---|"]
    for _, r in pf[pf["attack_packets"] == 0].iterrows():
        called = r.get(f"ml_{m0}_predicted_as")
        L.append(f"| {r['pcap'][:40]} | {r['packets']:,} | {fp(r['normal_wrongly_blocked'])} | "
                 f"{fp(r['normal_alerted'])} | {called if isinstance(called, str) else ''} |")
    if not shift.empty:
        L += ["", "## 5b. Feature shift: Edge-IIoTset normal rows vs CICIoT2023 Benign (training)", "",
              "Share of Edge normal rows outside the 1–99% range of CICIoT2023 Benign. High = the model never saw "
              "normal traffic like this.", "",
              "| Feature | Outside CIC range | CIC Benign median | Edge normal median |", "|---|---|---|---|"]
        for _, r in shift.head(15).iterrows():
            L.append(f"| {r['feature']} | {fp(r['edge_outside_cic_1_99'])} | {r['cic_benign_median']:.4g} | "
                     f"{r['edge_normal_median']:.4g} |")
    L += ["", "## 6. Cost", "", "| pcap | Suricata s | Suricata peak MB | Parse + features s |", "|---|---|---|---|"]
    for _, r in pf.iterrows():
        L.append(f"| {r['pcap'][:40]} | {r['suricata_s'] if pd.notna(r['suricata_s']) else 'n/a'} | "
                 f"{r['suricata_peak_mb'] if pd.notna(r['suricata_peak_mb']) else 'n/a'} | {r['parse_s']} |")
    L += ["", "## 7. Top Suricata signatures", "", "| Signature | Alerts |", "|---|---|"]
    L += [f"| {s} | {c:,} |" for s, c in top_sigs]
    L += ["", "## 8. Labels and simplifications", "",
          "- Labels: attack pcaps use the IP pairs labelled attack in the matching Edge-IIoTset CSV "
          "(label mode per file in per_file.csv); if that fails, the whole attack pcap counts as attack.",
          "- Suricata ran offline on the pcap; THREATS alerts (not 'SURICATA ', 'ET INFO', 'ET POLICY') are used "
          "as drops from the first alert of a flow on.",
          "- The ML ran once on the packets Suricata let through; packets removed later by quarantine were not "
          "fed back. The trust score (posture 60 / Suricata 25 / ML 15) is not simulated; the quarantine rule "
          "stands for the direct high-confidence ML action.",
          f"- Categories the model knows: {', '.join(model_cats)}. Ransomware is not in training (detection only).",
          "", "![pipeline](charts/01_pipeline_per_attack.png)"]
    (run_dir / "REPORT.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
