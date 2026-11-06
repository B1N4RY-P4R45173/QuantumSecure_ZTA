"""
Step 4 — Test the TRUST Lab models on CIC-IDS2017 flows made with the SAME flow tool as TRUST Lab.

    python step4_v4flows.py --day Wednesday \
        --flows /path/wed_py.csv \
        --v3-csv data/csv/Wednesday-workingHours.pcap_ISCX.csv

Why: on the original CIC-IDS2017 CSVs (CICFlowMeter v3, Java) SW-XGBoost (TRUST Lab) did badly.
Two possible reasons: a different flow tool, or a different network. TRUST Lab counts whole
packets (headers included) like the Python `cicflowmeter`; the Java tool counts payload only.
Here the flows come from the Python tool (see CICFLOWMETER.md), so only the network differs.

What it does:
1. Reads the Python cicflowmeter CSV, renames columns to TRUST Lab names.
2. Labels flows with the attack schedule taken from the v3 labelled CSV:
    for each attack label, its attacker/victim IP pairs and its first..last time.
    A flow is that attack if it is between one of those IP pairs (any direction) and starts
    inside that time (+- --pad seconds; v3 times have minutes only). Everything else = BENIGN.
3. Orders flows by start time, builds the same inputs as before (window 32), scores
    SW_XGB_TRUSTLAB and XGB_TRUSTLAB. No retraining.
4. Optional: matches Suricata alerts (output/<day>/suricata/eve.json) to the same flows,
    so Suricata and the models are scored on exactly the same flows.
5. Reports the test time blocks (same blocks as step 2) and the whole day.

Saves output/<day>/v4/: flows_v4.parquet, predictions_v4.parquet, RESULTS_V4.md, results_v4.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys

import numpy as np
import pandas as pd

import config as K
from cicids import load_flows

sys.path.insert(0, str(K.MODELS / "MODEL SURICATA"))
sys.path.insert(0, str(K.MODELS))
from common.windows import flow_only_features, sliding_window_features   # noqa: E402

LAB_TZ = "America/Moncton"                  # CIC-IDS2017 lab time (UTC-3 in July 2017)
NON_THREAT = re.compile(r"^(SURICATA |ET INFO|ET POLICY)")
SMALL_LABEL = 30


def norm(name: str) -> str:
    """'Flow Byts/s' -> 'flow_byts_s', the Python cicflowmeter column style."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


# ---------------------------------------------------------------- 1. load v4 flows
def load_v4(path: str, features: list[str]) -> tuple[pd.DataFrame, list[str]]:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    print(f"   {len(df):,} flows, {len(df.columns)} columns")
    for c in ("src_port", "dst_port", "protocol"):         # ID copies (dst_port/protocol are also features)
        df["id_" + c] = pd.to_numeric(df[c], errors="coerce").fillna(-1).astype(np.int64)
    by_norm = {norm(c): c for c in df.columns}
    rename = {by_norm[norm(f)]: f for f in features if norm(f) in by_norm}
    missing = [f for f in features if norm(f) not in by_norm]
    if missing:
        print(f"   WARNING: {len(missing)} model features not in the CSV, set to 0: {missing}")
    df = df.rename(columns=rename)
    for f in missing:
        df[f] = 0.0

    X = df[features].apply(pd.to_numeric, errors="coerce").to_numpy(np.float64, copy=True)
    X[~np.isfinite(X)] = 0.0
    df[features] = np.clip(X, -1e12, 1e12).astype(np.float32)

    df["ts"] = pd.to_numeric(df["timestamp"], errors="coerce")
    if df["ts"].isna().mean() > 0.5:
        raise SystemExit("timestamp is not Unix time; apply the timestamp fix in CICFLOWMETER.md and rerun")
    df = df.dropna(subset=["ts"])
    local = pd.to_datetime(df["ts"], unit="s", utc=True).dt.tz_convert(LAB_TZ)
    df["tod"] = (local.dt.hour * 3600 + local.dt.minute * 60 + local.dt.second
                + local.dt.microsecond / 1e6).to_numpy(np.float64)
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    return df, missing


def to_trustlab_rules(df: pd.DataFrame) -> list[str]:
    """Recompute the features whose TRUST Lab rule is known (each rule holds in 100% of 200,000
    TRUST Lab rows checked). The Python tool defines them differently.
    Fwd/Bwd Header Len = 40 x packets (TCP) or 28 x packets (UDP)
    Down/Up Ratio      = bwd bytes / fwd bytes (0 if no fwd bytes)
    Active/Idle Max    = flow duration in seconds; Active/Idle Mean = duration / 2
    The 6 bulk features use a hidden per-flow number K that cannot be computed from flow data;
    they are set to 0, the most common TRUST Lab value (60% of rows).
    """
    hdr = np.where(df["Protocol"] == 6, 40, np.where(df["Protocol"] == 17, 28, 0)).astype(np.float32)
    df["Fwd Header Len"] = hdr * df["Tot Fwd Pkts"]
    df["Bwd Header Len"] = hdr * df["Tot Bwd Pkts"]
    fwd = df["TotLen Fwd Pkts"].to_numpy(np.float64)
    df["Down/Up Ratio"] = np.where(fwd > 0, df["TotLen Bwd Pkts"].to_numpy(np.float64) / np.maximum(fwd, 1), 0)
    d = df["Flow Duration"].to_numpy(np.float64) / 1e6
    df["Active Max"] = df["Idle Max"] = d
    df["Active Mean"] = df["Idle Mean"] = d / 2
    bulk = ["Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
            "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"]
    for c in bulk:
        df[c] = 0.0
    changed = ["Fwd Header Len", "Bwd Header Len", "Down/Up Ratio", "Active Max", "Idle Max",
            "Active Mean", "Idle Mean"] + bulk
    df[changed] = df[changed].astype(np.float32)
    return changed


# ---------------------------------------------------------------- 2. labels
def pair_key(a: pd.Series, b: pd.Series) -> pd.Series:
    a, b = a.astype(str), b.astype(str)
    return pd.Series(np.where(a < b, a + "|" + b, b + "|" + a), index=a.index)


def main_cluster(tod: np.ndarray, gap: float) -> tuple[float, float, int]:
    """Biggest group of times with no hole longer than `gap` s. Drops stray mislabelled flows
    (the v3 CSV has e.g. a few 'DoS slowloris' flows hours away from the real attack)."""
    t = np.sort(tod)
    cut = np.flatnonzero(np.diff(t) > gap) + 1
    parts = np.split(t, cut)
    best = max(parts, key=len)
    return float(best[0]), float(best[-1]), len(t) - len(best)


def schedule_from_v3(v3: pd.DataFrame, min_share: float, gap: float) -> pd.DataFrame:
    """Per attack label: IP pairs (with >= min_share of the label's flows) and the main time block."""
    att = v3[v3["Label"] != "BENIGN"].copy()
    att["pair"] = pair_key(att["Source IP"], att["Destination IP"])
    rows = []
    for lab, g in att.groupby("Label"):
        share = g["pair"].value_counts(normalize=True)
        for pair, s in share.items():
            if s < min_share:
                continue
            gp = g[g["pair"] == pair]
            start, end, dropped = main_cluster(gp["tod"].to_numpy(), gap)
            rows.append({"label": lab, "pair": pair, "v3_flows": len(gp), "dropped_outliers": dropped,
                        "start": start, "end": end + 60})          # v3 times have minutes only
    return pd.DataFrame(rows)


def label_flows(df: pd.DataFrame, sched: pd.DataFrame, pad: float) -> np.ndarray:
    pair = pair_key(df["src_ip"], df["dst_ip"]).to_numpy()
    tod = df["tod"].to_numpy()
    lab = np.full(len(df), "BENIGN", dtype=object)
    for r in sched.itertuples():
        m = (pair == r.pair) & (tod >= r.start - pad) & (tod <= r.end + pad)
        clash = m & (lab != "BENIGN")
        if clash.any():
            print(f"   NOTE: {clash.sum():,} flows match two attacks; kept the first label")
        lab[m & (lab == "BENIGN")] = r.label
    return lab


def hms(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


# ---------------------------------------------------------------- 3. models
def score_model(model_dir, df: pd.DataFrame) -> np.ndarray:
    import xgboost as xgb

    info = json.loads((model_dir / "model_info.json").read_text(encoding="utf-8"))
    builder = sliding_window_features if info["windowed"] else flow_only_features
    X, _ = builder(df, info["base_features"], K.WINDOW)
    booster = xgb.Booster()
    booster.load_model(str(model_dir / info["model_file"]))
    booster.set_param({"device": "cpu"})
    prob = booster.predict(xgb.DMatrix(X)).reshape(len(X), -1)
    return np.array(info["classes"])[prob.argmax(1)]


# ---------------------------------------------------------------- 4. Suricata
def suricata_hits(df: pd.DataFrame, eve, tol: float) -> dict[str, np.ndarray]:
    from run_suricata import read_alerts

    alerts = read_alerts(eve)
    print(f"   {len(alerts):,} alerts in {eve}")
    alerts["threat"] = ~alerts["signature"].astype(str).str.match(NON_THREAT)

    def key(proto, ip1, port1, ip2, port2):
        e1 = ip1.astype(str) + ":" + port1.astype(str)
        e2 = ip2.astype(str) + ":" + port2.astype(str)
        return proto.astype(str) + "|" + np.where(e1 < e2, e1 + "|" + e2, e2 + "|" + e1)

    fk = key(df["id_protocol"], df["src_ip"], df["id_src_port"], df["dst_ip"], df["id_dst_port"])
    ak = key(alerts["proto"], alerts["a"].map(lambda t: t[0]), alerts["a"].map(lambda t: int(t[1] or 0)),
            alerts["b"].map(lambda t: t[0]), alerts["b"].map(lambda t: int(t[1] or 0)))
    out = {}
    for name, sel in (("SURICATA_THREATS", alerts["threat"].to_numpy()), ("SURICATA_ALL", None)):
        a = pd.DataFrame({"key": ak, "ats": alerts["ts"].to_numpy()})
        if sel is not None:
            a = a[sel]
        f = pd.DataFrame({"key": fk, "flow": np.arange(len(df)), "start": df["ts"].to_numpy(),
                        "end": df["ts"].to_numpy() + df["Flow Duration"].to_numpy(np.float64) / 1e6})
        p = f.merge(a, on="key", how="inner")
        ok = (p["ats"] >= p["start"] - tol) & (p["ats"] <= p["end"] + tol)
        hit = np.zeros(len(df), bool)
        hit[p.loc[ok, "flow"].unique()] = True
        out[name] = hit
        print(f"   {name}: {hit.sum():,} flows with an alert")
    return out


# ---------------------------------------------------------------- 5. report
def metrics(is_att: np.ndarray, flagged: np.ndarray) -> dict:
    tp = int((is_att & flagged).sum()); fn = int((is_att & ~flagged).sum())
    fp = int((~is_att & flagged).sum()); tn = int((~is_att & ~flagged).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"detection_rate": rec, "false_alarm_rate": fp / (fp + tn) if fp + tn else 0.0,
            "precision": prec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn}


def pct(v: float) -> str:
    return f"{100 * v:.2f}%"


def old_v3_rows(day_dir) -> dict:
    """SW_XGB_TRUSTLAB / XGB_TRUSTLAB on the old v3 CSV test flows, if step 2 output exists."""
    fp, pp = day_dir / "flows.parquet", day_dir / "xgb_predictions.parquet"
    if not (fp.exists() and pp.exists()):
        return {}
    flows, preds = pd.read_parquet(fp), pd.read_parquet(pp)
    y = flows.loc[preds.index, "is_attack"].to_numpy().astype(bool)
    rows = {}
    for col, name in (("sw_xgb_trustlab", "SW_XGB_TRUSTLAB"), ("xgb_trustlab", "XGB_TRUSTLAB")):
        if col in preds:
            rows[name] = metrics(y, preds[col].to_numpy() != "Benign")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--flows", required=True, help="Python cicflowmeter CSV of this day")
    ap.add_argument("--v3-csv", nargs="+", required=True, help="CIC-IDS2017 labelled CSV(s), for the schedule")
    ap.add_argument("--pad", type=float, default=60.0, help="seconds added around each attack time")
    ap.add_argument("--min-share", type=float, default=0.05,
                    help="ignore IP pairs with less than this share of a label's v3 flows (label noise)")
    ap.add_argument("--gap", type=float, default=600.0,
                    help="v3 attack flows more than this many seconds away from the main block are ignored")
    ap.add_argument("--raw", action="store_true",
                    help="use the Python tool's own feature values (no conversion to TRUST Lab rules)")
    ap.add_argument("--tolerance", type=float, default=1.0, help="Suricata alert time tolerance, seconds")
    ap.add_argument("--no-suricata", action="store_true")
    args = ap.parse_args()
    day_dir = K.OUT / args.day
    out = day_dir / ("v4_raw" if args.raw else "v4")
    out.mkdir(parents=True, exist_ok=True)

    sw_info = json.loads((K.SW_XGB_DIR / "model_info.json").read_text(encoding="utf-8"))
    feats = sw_info["base_features"]

    print("1) loading Python cicflowmeter flows ...")
    df, missing = load_v4(args.flows, feats)
    if not args.raw:
        changed = to_trustlab_rules(df)
        print(f"   recomputed with TRUST Lab rules: {changed}")

    print("2) attack schedule from the v3 labelled CSV ...")
    v3 = load_flows(args.v3_csv)
    sched = schedule_from_v3(v3, args.min_share, args.gap)
    for r in sched.itertuples():
        print(f"   {r.label:20s} {r.pair:32s} {hms(r.start)} - {hms(r.end)}  ({r.v3_flows:,} v3 flows, "
            f"{r.dropped_outliers:,} stray flows ignored)")
    df["Label"] = label_flows(df, sched, args.pad)
    df["is_attack"] = (df["Label"] != "BENIGN").astype(np.int8)
    block = (df["tod"].to_numpy() // (K.BLOCK_MINUTES * 60)).astype(np.int64)
    df["split"] = np.array(K.BLOCK_PATTERN, dtype=object)[block % len(K.BLOCK_PATTERN)]
    df.loc[df.index[:K.WINDOW - 1], "split"] = "skip"
    print("   v4 labels:\n" + df["Label"].value_counts().to_string())

    print("3) scoring TRUST Lab models (no retraining) ...")
    scored = df.index[K.WINDOW - 1:]
    preds = pd.DataFrame(index=scored)
    for name, model_dir in (("SW_XGB_TRUSTLAB", K.SW_XGB_DIR), ("SW_XGB_ROBUST", K.SW_XGB_ROBUST_DIR),
                            ("XGB_TRUSTLAB", K.TRUST_XGB_DIR)):
        if not (model_dir / "model_info.json").exists():
            print(f"   {name}: skipped (no model in {model_dir})")
            continue
        preds[name] = score_model(model_dir, df)
        print(f"   {name}: done")

    eve = day_dir / "suricata" / "eve.json"
    if not args.no_suricata and eve.exists():
        print("4) matching Suricata alerts to the same flows ...")
        for name, hit in suricata_hits(df, eve, args.tolerance).items():
            preds[name] = np.where(hit[scored], "Attack", "Benign")
    elif not args.no_suricata:
        print(f"4) Suricata skipped: {eve} not found")

    keep = ["src_ip", "id_src_port", "dst_ip", "id_dst_port", "id_protocol", "ts", "tod",
            "Flow Duration", "Label", "is_attack", "split"]
    df[keep].to_parquet(out / "flows_v4.parquet")
    preds.to_parquet(out / "predictions_v4.parquet")

    # ------------------------------------------------------------ report
    dets = list(preds.columns)
    res = {}
    L = [f"# TRUST Lab models vs Suricata — CIC-IDS2017 {args.day}, flows from the TRUST Lab flow tool", "",
        "Flows made with the Python `cicflowmeter` (whole-packet lengths, like TRUST Lab), "
        "labelled with the attack schedule from the v3 CSV. Models are NOT retrained on CIC-IDS2017.",
        "", ("Feature values: **raw Python tool values**." if args.raw else
            "Feature values: 7 features recomputed with TRUST Lab's own rules; the 6 bulk features "
            "cannot be reproduced and are set to 0. SW_XGB_ROBUST is trained without the 6 bulk features."), ""]
    for part, rows in (("test time blocks (same blocks as step 2)", df.loc[scored, "split"] == "test"),
                    ("whole day", pd.Series(True, index=scored))):
        idx = scored[rows.to_numpy()]
        y = df.loc[idx, "is_attack"].to_numpy().astype(bool)
        res[part] = {}
        L += [f"## {part[0].upper() + part[1:]}: {len(idx):,} flows, {int(y.sum()):,} attack", "",
            "| Detector | Detection rate | False alarm rate | Precision | F1 | Missed attacks | False alarms |",
            "|---|---|---|---|---|---|---|"]
        for d in dets:
            m = metrics(y, preds.loc[idx, d].to_numpy() != "Benign")
            res[part][d] = m
            L.append(f"| {d} | {pct(m['detection_rate'])} | {pct(m['false_alarm_rate'])} | {pct(m['precision'])} "
                    f"| {m['f1']:.4f} | {m['fn']:,} | {m['fp']:,} |")
        labs = [l for l in df.loc[idx, "Label"].value_counts().index if l != "BENIGN"]
        if labs:
            L += ["", "Detected per attack (share of its flows flagged as any attack):", "",
                "| Attack | Flows | " + " | ".join(dets) + " |", "|---|---|" + "---|" * len(dets)]
            for lab in labs:
                m = df.loc[idx, "Label"].to_numpy() == lab
                small = " ⚠️" if m.sum() < SMALL_LABEL else ""
                cells = [pct((preds.loc[idx, d].to_numpy()[m] != "Benign").mean()) for d in dets]
                L.append(f"| {lab}{small} | {int(m.sum()):,} | " + " | ".join(cells) + " |")
        L.append("")

    old = old_v3_rows(day_dir)
    if old:
        new = res["test time blocks (same blocks as step 2)"]
        L += ["## Same model, old flows (v3 Java) vs new flows (TRUST Lab tool) — test blocks", "",
            "| Detector | Flows | Detection rate | False alarm rate |", "|---|---|---|---|"]
        for name, m in old.items():
            L.append(f"| {name} | v3 CSV (old) | {pct(m['detection_rate'])} | {pct(m['false_alarm_rate'])} |")
            if name in new:
                n = new[name]
                L.append(f"| {name} | **TRUST Lab tool (new)** | {pct(n['detection_rate'])} | {pct(n['false_alarm_rate'])} |")
        L.append("")

    L += ["## Notes", "",
        f"- Attack schedule taken from the v3 labelled CSV (pairs with ≥{args.min_share:.0%} of a label's flows, "
        f"times ± {args.pad:.0f} s). v3 has known label errors (Engelen et al., 2021).",
        "- The two flow tools cut traffic into flows differently, so flow counts differ from the v3 CSV.",
        f"- Suricata: a flow counts as detected if an alert with the same endpoints falls inside the flow "
        f"(± {args.tolerance:g} s). SURICATA_THREATS ignores engine events and ET INFO / ET POLICY rules.",
        f"- ⚠️ = fewer than {SMALL_LABEL} flows, percentage not reliable."]
    if missing:
        L.append(f"- Model features missing from the CSV (set to 0): {missing}")
    text = "\n".join(L) + "\n"
    (out / "RESULTS_V4.md").write_text(text, encoding="utf-8")
    (out / "results_v4.json").write_text(json.dumps(
        {"schedule": sched.to_dict("records"), "results": res, "old_v3": old,
        "missing_features": missing, "settings": vars(args)}, indent=2, default=str), encoding="utf-8")
    print("\n" + text)
    print(f"saved: {out}")


if __name__ == "__main__":
    main()
