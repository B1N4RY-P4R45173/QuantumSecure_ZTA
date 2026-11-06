"""
Phase 4: LightGBM BAL_MS (trained on TRUST Lab only) vs Suricata on CIC-IDS2017, Tuesday to Friday.
CIC-IDS2017 is TEST data only: new to both detectors, nothing is retrained.

    python MODELS/Suricata/cicids_week_eval.py
    python MODELS/Suricata/cicids_week_eval.py --flows-dir runs/cicids_pyflows_<ts>/flows

Per day:
  1. Python cicflowmeter flows (full-frame lengths, like TRUST Lab) -> TRUST Lab names and rules
     (step4_v4flows.py: header length, Down/Up, Active/Idle).
  2. Labels from the attack schedule in the v3 labelled CSVs (attacker/victim IP pair + time).
  3. Detectors on the SAME flows (all scored from the same first row):
       BAL_MS          LightGBM BAL_MS, no bulk (the Phase 1 choice)
       FLAT            plain LightGBM, no bulk (reference: no window)
       SURICATA_ALL    any Suricata alert on the flow (ET Open rules)
       SURICATA_THREATS same, without engine events / ET INFO / ET POLICY
  4. Detection rate, false alarm rate, precision, F1, per attack label, time to first alert.
Week = all 4 days together. Speed/RAM: Suricata perf.json per day; BAL_MS live latency run.

Saves: runs/cicids_week_eval_<YYYYMMDD_HHMMSS>/
       run.log, config.json, results.json, WEEK_RESULTS.md, charts/*.png, per_day/<Day>_predictions.parquet
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
MODELS_DIR = HERE.parent
PROJECT_ROOT = MODELS_DIR.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(MODELS_DIR))
sys.path.insert(0, str(MODELS_DIR / "MODEL SW_XGBOOST"))

import window_tradeoff as wt                                            # noqa: E402
from train_balanced import build_X                                      # noqa: E402
import config as K                                                      # noqa: E402
from cicids import load_flows                                           # noqa: E402
from step4_v4flows import (LAB_TZ, label_flows, metrics, norm, schedule_from_v3,  # noqa: E402
                           suricata_hits, to_trustlab_rules)

# ---------------------------------------------------------------- settings
DATASET_DIR = PROJECT_ROOT / "DataSet"
RUNS_DIR = PROJECT_ROOT / "runs"
SCRIPT_NAME = "cicids_week_eval"
MODEL_RUN = "runs/sw_lgbm_balanced_nobulk_20261031_121031"
LIVE_RUN = "runs/live_latency_20261031_122954"
WEDNESDAY_FLOWS = DATASET_DIR / "wed_py" / "wed_py.csv"
DAYS = ["Tuesday", "Wednesday", "Thursday", "Friday"]          # Monday has no attacks (user: skip it)
V3_CSVS = {
    "Tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv"],
    "Wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
    "Thursday": ["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                 "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"],
    "Friday": ["Friday-WorkingHours-Morning.pcap_ISCX.csv", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
               "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"],
}
PAD_S, MIN_SHARE, GAP_S, ALERT_TOL_S = 60.0, 0.05, 600.0, 1.0       # same as step4_v4flows.py defaults
DETECTORS = ["BAL_MS", "FLAT", "SURICATA_ALL", "SURICATA_THREATS"]
SMALL_LABEL = 30                                                       # labels with fewer flows are marked ⚠
CHART_FILES = ["01_per_day.png", "02_per_attack_week.png"]


# ---------------------------------------------------------------- 1. flows
def to_unix(s: pd.Series) -> np.ndarray:
    """Unix seconds. Numeric -> as is. Text -> read as the local time of the PC that ran cicflowmeter."""
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.9:
        return num.to_numpy(np.float64)
    local_tz = datetime.now().astimezone().tzinfo
    t = pd.to_datetime(s, errors="coerce").dt.tz_localize(local_tz)
    return (t.dt.tz_convert("UTC") - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().to_numpy(np.float64)


def load_pyflows(path: Path, feats: list[str], log) -> tuple[pd.DataFrame, list[str]]:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    for c in ("src_port", "dst_port", "protocol"):
        df["id_" + c] = pd.to_numeric(df[c], errors="coerce").fillna(-1).astype(np.int64)
    by_norm = {norm(c): c for c in df.columns}
    rename = {by_norm[norm(f)]: f for f in feats if norm(f) in by_norm}
    missing = [f for f in feats if norm(f) not in by_norm]
    df = df.rename(columns=rename)
    for f in missing:
        df[f] = 0.0
    for f in ("Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Protocol", "Flow Duration"):
        if f not in df:                                   # needed by to_trustlab_rules
            df[f] = pd.to_numeric(df[by_norm[norm(f)]], errors="coerce") if norm(f) in by_norm else 0.0
    X = df[feats].apply(pd.to_numeric, errors="coerce").to_numpy(np.float64, copy=True)
    X[~np.isfinite(X)] = 0.0                              # same cleaning as TRUST Lab preprocessing
    df[feats] = np.clip(X, -1e12, 1e12).astype(np.float32)
    df["ts"] = to_unix(df["timestamp"])
    df = df.dropna(subset=["ts"])
    local = pd.to_datetime(df["ts"], unit="s", utc=True).dt.tz_convert(LAB_TZ)
    df["tod"] = (local.dt.hour * 3600 + local.dt.minute * 60 + local.dt.second
                 + local.dt.microsecond / 1e6).to_numpy(np.float64)
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    log.info("   %s flows, %d model features missing (set to 0): %s", f"{len(df):,}", len(missing), missing or "none")
    return df, missing


# ---------------------------------------------------------------- 2. models
def load_models(model_run: Path) -> dict:
    import lightgbm as lgb
    from common import config as C
    out = {}
    for name in ("BAL_MS", "FLAT"):
        d = model_run / "models" / name
        info = json.loads((d / "model_info.json").read_text(encoding="utf-8"))
        out[name] = {"info": info, "booster": lgb.Booster(model_file=str(d / info["model_file"])),
                     "ids": np.array([C.CLASS_TO_ID[c] for c in info["classes"]]),
                     "classes": np.array(info["classes"])}
    return out


def predict(m: dict, df: pd.DataFrame, start: int) -> np.ndarray:
    X = build_X(df, m["info"]["base_features"], m["info"]["spec"], start)
    return m["classes"][m["booster"].predict(X).argmax(1)]


# ---------------------------------------------------------------- 3. scoring
def first_alert(labels: np.ndarray, flagged: np.ndarray, ts: np.ndarray) -> dict:
    """Per attack label: attack flows (in time order) before the first flagged one, and seconds."""
    out = {}
    for lab in np.unique(labels):
        if lab == "BENIGN":
            continue
        idx = np.flatnonzero(labels == lab)
        hit = np.flatnonzero(flagged[idx])
        out[lab] = ({"flows_before_first_alert": int(hit[0]), "seconds_to_first_alert": float(ts[idx[hit[0]]] - ts[idx[0]])}
                    if len(hit) else {"flows_before_first_alert": None, "seconds_to_first_alert": None})
    return out


def score_day(labels: np.ndarray, flags: dict, pred_class: dict, ts: np.ndarray) -> dict:
    is_att = labels != "BENIGN"
    res = {}
    for det, f in flags.items():
        r = metrics(is_att, f)
        r["per_label"] = {lab: {"flows": int((labels == lab).sum()), "detected": float(f[labels == lab].mean())}
                          for lab in np.unique(labels)}
        r["first_alert"] = first_alert(labels, f, ts)
        if det in pred_class:                         # ML only: named as the closest TRUST Lab class?
            pc = pred_class[det]
            r["closest_class_named"] = {lab: float((pc[labels == lab] == K.CIC_TO_TRUST_CLASS.get(lab, "?")).mean())
                                        for lab in np.unique(labels) if lab != "BENIGN"}
            # what the model actually called each CIC label (top 3 TRUST Lab classes), to explain misses/false alarms
            r["predicted_as"] = {lab: {k: round(float(v), 4) for k, v in
                                       pd.Series(pc[labels == lab]).value_counts(normalize=True).head(3).items()}
                                 for lab in np.unique(labels)}
        res[det] = r
    return res


def add_counts(a: dict, b: dict) -> dict:
    return {k: a.get(k, 0) + b[k] for k in ("tp", "fn", "fp", "tn")}


def from_counts(c: dict) -> dict:
    tp, fn, fp, tn = c["tp"], c["fn"], c["fp"], c["tn"]
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {**c, "detection_rate": rec, "false_alarm_rate": fp / (fp + tn) if fp + tn else 0.0,
            "precision": prec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0}


# ---------------------------------------------------------------- report
def pct(v) -> str:
    return "–" if v is None else f"{100 * v:.2f}%"


def report(days: dict, week: dict, per_label_week: dict, costs: dict, sanity: dict) -> str:
    L = ["# CIC-IDS2017 week (Tuesday–Friday): LightGBM BAL_MS vs Suricata", "",
         "CIC-IDS2017 is **test data only**: new to both detectors. BAL_MS was trained on TRUST Lab only "
         "(no bulk features). Flows: Python cicflowmeter (full-frame lengths, like TRUST Lab) + TRUST Lab rules. "
         "Every detector is scored on the **same flows**.", "",
         "## 1. Whole week (all 4 days together)", "",
         "| Detector | Detection rate | False alarm rate | Precision | F1 | Missed attacks | False alarms |",
         "|---|---|---|---|---|---|---|"]
    for det in DETECTORS:
        w = week[det]
        L.append(f"| {det} | {pct(w['detection_rate'])} | {pct(w['false_alarm_rate'])} | {pct(w['precision'])} "
                 f"| {w['f1']:.4f} | {w['fn']:,} | {w['fp']:,} |")
    L += ["", "## 2. Per day", ""]
    for day, r in days.items():
        s = sanity[day]
        L += [f"### {day}", "",
              f"{s['scored_flows']:,} flows scored, {s['attack_flows']:,} attack. "
              f"Labels: {', '.join(f'{k} {v:,}' for k, v in s['labels'].items() if k != 'BENIGN')}.", "",
              "| Detector | Detection rate | False alarm rate | Precision | F1 | Missed | False alarms |",
              "|---|---|---|---|---|---|---|"]
        for det in DETECTORS:
            m = r[det]
            L.append(f"| {det} | {pct(m['detection_rate'])} | {pct(m['false_alarm_rate'])} | {pct(m['precision'])} "
                     f"| {m['f1']:.4f} | {m['fn']:,} | {m['fp']:,} |")
        L.append("")
    L += ["## 3. Per attack (whole week): share of the attack's flows flagged", "",
          "| Attack | Day | Flows | " + " | ".join(DETECTORS) + " | BAL_MS named closest TRUST class |",
          "|---|---|---|" + "---|" * len(DETECTORS) + "---|"]
    for lab, r in per_label_week.items():
        warn = " ⚠" if r["flows"] < SMALL_LABEL else ""
        L.append(f"| {lab}{warn} | {r['day']} | {r['flows']:,} | " + " | ".join(pct(r[d]) for d in DETECTORS)
                 + f" | {pct(r.get('bal_named'))} ({K.CIC_TO_TRUST_CLASS.get(lab, '?')}) |")
    L += ["", "### What the ML models called each label (top 3 TRUST Lab classes, share of its flows)", "",
          "| Label | Day | BAL_MS predicted as | FLAT predicted as |", "|---|---|---|---|"]
    for day, r in days.items():
        for lab in r["BAL_MS"].get("predicted_as", {}):
            cells = [", ".join(f"{k} {100 * v:.1f}%" for k, v in r[d]["predicted_as"][lab].items())
                     for d in ("BAL_MS", "FLAT")]
            L.append(f"| {lab} | {day} | {cells[0]} | {cells[1]} |")
    L += ["", "## 4. Time to first alert (attack flows that passed before the first alert)", "",
          "| Attack | " + " | ".join(DETECTORS) + " |", "|---|" + "---|" * len(DETECTORS)]
    for lab, r in per_label_week.items():
        cells = []
        for d in DETECTORS:
            fa = r["first_alert"][d]
            cells.append("never" if fa["flows_before_first_alert"] is None
                         else f"{fa['flows_before_first_alert']:,} flows / {fa['seconds_to_first_alert']:.0f} s")
        L.append(f"| {lab} | " + " | ".join(cells) + " |")
    L += ["", "## 5. Speed and resources", "",
          "| Day | Suricata packets/s | Suricata peak RAM (MB) | Suricata time (s) | Flows | BAL_MS time at 1 thread (s) |",
          "|---|---|---|---|---|---|"]
    for day, c in costs["days"].items():
        L.append(f"| {day} | {wt.fmt(c.get('suricata_packets_per_s'), 'f0')} | {wt.fmt(c.get('suricata_peak_ram_mb'), 'f0')} "
                 f"| {wt.fmt(c.get('suricata_engine_s'), 'f0')} | {c['flows']:,} | {wt.fmt(c.get('bal_ms_seconds'), 'f0')} |")
    b = costs["bal_ms"]
    L += ["", f"BAL_MS live (1 thread): {wt.fmt(b.get('total_us_median'), 'f0')} µs per flow, max "
              f"{wt.fmt(b.get('max_flows_per_s'), 'f0')} flows/s without drops, about 206 MB RAM "
              "(from the live latency run). BAL_MS needs CICFlowMeter first (not counted); Suricata reads packets directly.",
          "", "## 6. Who wins in which segment (week)", "", "| Segment | Winner | Numbers |", "|---|---|---|"]
    for seg, (win, txt) in costs["segments"].items():
        L.append(f"| {seg} | **{win}** | {txt} |")
    L += ["", "## 7. Charts", ""] + [f"![{c}](charts/{c})" for c in CHART_FILES]
    L += ["", "## Notes", "",
          "- Labels come from the v3 CSV attack schedule (IP pair + time ± 60 s); this can mislabel some flows.",
          f"- Attacks with fewer than {SMALL_LABEL} flows are marked ⚠: their percentages are rough.",
          "- Suricata flags a flow if any alert matches its 5-tuple within its time (± 1 s). SURICATA_ALL counts "
          "every alert, including engine events and policy rules, so its false alarms are high by design.",
          "- 'Named closest TRUST class' uses the CIC→TRUST mapping in config.py (for example DoS Hulk → DoS); "
          "detection itself is attack vs normal."]
    return "\n".join(L) + "\n"


def make_charts(days: dict, per_label_week: dict, out_dir: Path, log) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import PercentFormatter
    except ImportError:
        log.warning("matplotlib not installed: charts skipped")
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "figure.facecolor": wt.SURFACE, "axes.facecolor": wt.SURFACE, "savefig.facecolor": wt.SURFACE,
        "axes.edgecolor": wt.GRID, "axes.grid": True, "axes.grid.axis": "y", "grid.color": wt.GRID,
        "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True,
        "text.color": wt.INK, "axes.labelcolor": wt.INK2, "xtick.color": wt.INK2, "ytick.color": wt.INK2,
        "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold", "legend.frameon": False,
    })
    names = list(days)
    x = np.arange(len(names))
    w = 0.8 / len(DETECTORS)
    fig, axs = plt.subplots(1, 2, figsize=(13, 4.8))
    fig.suptitle("CIC-IDS2017, per day: LightGBM BAL_MS vs Suricata (same flows)", fontweight="bold", x=0.01, ha="left")
    for ax, (key, title) in zip(axs, [("detection_rate", "Detection rate (higher is better)"),
                                      ("false_alarm_rate", "False alarm rate (lower is better)")]):
        for i, det in enumerate(DETECTORS):
            ax.bar(x + (i - (len(DETECTORS) - 1) / 2) * w, [days[d][det][key] for d in names], w * 0.92,
                   color=wt.SLOT[i], label=det)
        ax.set_xticks(x, names)
        ax.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
        ax.set_title(title, loc="left")
    h, lab = axs[0].get_legend_handles_labels()
    fig.legend(h, lab, loc="lower center", ncol=len(DETECTORS), bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=(0, 0.07, 1, 0.94))
    fig.savefig(out_dir / CHART_FILES[0], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[0])

    labs = list(per_label_week)
    M = np.array([[per_label_week[l][d] for d in DETECTORS] for l in labs])
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("blue", wt.BLUE_RAMP)
    fig, ax = plt.subplots(figsize=(8.5, 0.42 * len(labs) + 1.8))
    im = ax.imshow(M, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(DETECTORS)), DETECTORS)
    ax.set_yticks(range(len(labs)), [f"{l} ({per_label_week[l]['day'][:3]})" for l in labs])
    ax.grid(False)
    for i in range(len(labs)):
        for j in range(len(DETECTORS)):
            ax.text(j, i, f"{100 * M[i, j]:.1f}", ha="center", va="center", fontsize=8,
                    color=wt.SURFACE if M[i, j] > 0.55 else wt.INK)
    ax.set_title("Share of each attack's flows flagged (%), whole week", loc="left")
    fig.colorbar(im, ax=ax, fraction=0.04, format=PercentFormatter(1.0, decimals=0))
    fig.tight_layout()
    fig.savefig(out_dir / CHART_FILES[1], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[1])


def segments(week: dict, per_label_week: dict, costs: dict) -> dict:
    ml, sur = "BAL_MS", ["SURICATA_ALL", "SURICATA_THREATS"]
    seg = {}
    best_det = max(DETECTORS, key=lambda d: week[d]["detection_rate"])
    seg["Catching attacks (detection rate)"] = (best_det, ", ".join(f"{d} {pct(week[d]['detection_rate'])}" for d in DETECTORS))
    best_fa = min(DETECTORS, key=lambda d: week[d]["false_alarm_rate"])
    seg["Few false alarms"] = (best_fa, ", ".join(f"{d} {pct(week[d]['false_alarm_rate'])}" for d in DETECTORS))
    best_f1 = max(DETECTORS, key=lambda d: week[d]["f1"])
    seg["Overall balance (F1)"] = (best_f1, ", ".join(f"{d} {week[d]['f1']:.3f}" for d in DETECTORS))
    for lab, r in per_label_week.items():
        b = max([ml] + sur, key=lambda d: r[d])
        seg[f"Attack: {lab}"] = (b if r[b] > 0 else "none", ", ".join(f"{d} {pct(r[d])}" for d in [ml] + sur))
    seg["Speed / RAM"] = ("see section 5", "BAL_MS: about 4,000 flows/s on 1 thread, about 206 MB, but needs CICFlowMeter first; "
                          "Suricata: reads packets directly, can block the first packet, about 570–980 MB")
    seg["Adding a new attack"] = ("Suricata (if a rule exists)", "Suricata: add a rule; BAL_MS: needs labelled data and retraining")
    return seg


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="BAL_MS vs Suricata on the CIC-IDS2017 week")
    ap.add_argument("--flows-dir", default=None, help="folder with <Day>_py.csv (default: newest runs/cicids_pyflows_*/flows)")
    ap.add_argument("--model-run", default=MODEL_RUN)
    ap.add_argument("--live-run", default=LIVE_RUN)
    ap.add_argument("--days", nargs="+", default=DAYS, choices=DAYS)
    args = ap.parse_args()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    (run_dir / "per_day").mkdir(parents=True, exist_ok=False)
    log = wt.setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    try:
        np.random.seed(42)
        env = wt.log_environment(log)
        flows_dir = Path(args.flows_dir) if args.flows_dir else None
        if flows_dir is None:
            cands = sorted(RUNS_DIR.glob("cicids_pyflows_*/flows"))
            flows_dir = cands[-1] if cands else None
        flow_files = {}
        for d in args.days:
            p = flows_dir / f"{d}_py.csv" if flows_dir else None
            flow_files[d] = p if p and p.exists() else (WEDNESDAY_FLOWS if d == "Wednesday" else None)
            if flow_files[d] is None or not flow_files[d].exists():
                raise SystemExit(f"{d}: no Python cicflowmeter CSV (looked in {flows_dir}); run cicids_pyflows.py first")
        model_run = (PROJECT_ROOT / args.model_run).resolve()
        models = load_models(model_run)
        feats = models["BAL_MS"]["info"]["base_features"]
        start = max(models["BAL_MS"]["info"]["spec"]["windows"]) - 1
        config = {"script": SCRIPT_NAME, "days": args.days, "flow_files": {d: str(p) for d, p in flow_files.items()},
                  "v3_csvs": V3_CSVS, "model_run": str(model_run), "n_model_features": len(feats),
                  "scored_from_row": start, "pad_s": PAD_S, "min_share": MIN_SHARE, "gap_s": GAP_S,
                  "alert_tolerance_s": ALERT_TOL_S, "environment": env}
        wt.write_json(run_dir / "config.json", config)
        log.info("days %s | model %s | %d features | scored from row %d", args.days, model_run.name, len(feats), start)

        live = json.loads(((PROJECT_ROOT / args.live_run) / "results.json").read_text(encoding="utf-8"))
        bal_live = next((m for m in live["models"] if m["label"] == "LGBM BAL_MS (no bulk)"), {})
        bal_cost = {"total_us_median": wt.g(bal_live, "timing.total_us_median"), "max_flows_per_s": bal_live.get("max_flows_per_s")}

        days, sanity, costs_days = {}, {}, {}
        week_counts = {d: {} for d in DETECTORS}
        per_label_week: dict = {}
        for day in args.days:
            log.info("== %s ==", day)
            df, missing = load_pyflows(flow_files[day], feats, log)
            to_trustlab_rules(df)
            v3 = load_flows([str(DATASET_DIR / f) for f in V3_CSVS[day]])
            sched = schedule_from_v3(v3, MIN_SHARE, GAP_S)
            df["Label"] = label_flows(df, sched, PAD_S)
            del v3
            sl = slice(start, None)
            labels = df["Label"].to_numpy()[sl]
            ts = df["ts"].to_numpy()[sl]
            preds = {n: predict(m, df, start) for n, m in models.items()}
            flags = {n: p != "Benign" for n, p in preds.items()}
            eve = K.OUT / day / "suricata" / "eve.json"
            for name, hit in suricata_hits(df, eve, ALERT_TOL_S).items():
                flags[name] = hit[sl]
            days[day] = score_day(labels, flags, preds, ts)
            lab_counts = pd.Series(labels).value_counts()
            sanity[day] = {"scored_flows": int(len(labels)), "attack_flows": int((labels != "BENIGN").sum()),
                           "labels": {k: int(v) for k, v in lab_counts.items()}, "missing_features": missing,
                           "schedule_rows": int(len(sched))}
            for det in DETECTORS:
                week_counts[det] = add_counts(week_counts[det], days[day][det])
            for lab in lab_counts.index:
                if lab == "BENIGN":
                    continue
                key = lab if lab not in per_label_week else f"{lab} ({day})"
                r = {"day": day, "flows": int(lab_counts[lab]),
                     "first_alert": {d: days[day][d]["first_alert"][lab] for d in DETECTORS},
                     "bal_named": days[day]["BAL_MS"]["closest_class_named"].get(lab)}
                r.update({d: days[day][d]["per_label"][lab]["detected"] for d in DETECTORS})
                per_label_week[key] = r
            perf_p = K.OUT / day / "suricata" / "perf.json"
            perf = json.loads(perf_p.read_text(encoding="utf-8")) if perf_p.exists() else {}
            n = int(len(df))
            costs_days[day] = {"flows": n, "suricata_packets_per_s": perf.get("packets_per_s"),
                               "suricata_peak_ram_mb": perf.get("peak_ram_mb"), "suricata_engine_s": perf.get("engine_s"),
                               "bal_ms_seconds": (n * bal_cost["total_us_median"] / 1e6) if bal_cost["total_us_median"] else None}
            pd.DataFrame({"ts": ts, "Label": labels, **{f"pred_{k}": v for k, v in preds.items()},
                          **{f"flag_{k}": v for k, v in flags.items()}}).to_parquet(run_dir / "per_day" / f"{day}_predictions.parquet")
            for det in DETECTORS:
                m = days[day][det]
                log.info("   %-17s detection %s | false alarms %s | precision %s | F1 %.4f", det,
                         pct(m["detection_rate"]), pct(m["false_alarm_rate"]), pct(m["precision"]), m["f1"])
            wt.write_json(run_dir / "results.json", {**out, "days": days, "sanity": sanity})   # progress
            del df

        week = {d: from_counts(week_counts[d]) for d in DETECTORS}
        costs = {"days": costs_days, "bal_ms": bal_cost}
        costs["segments"] = segments(week, per_label_week, costs)
        (run_dir / "WEEK_RESULTS.md").write_text(report(days, week, per_label_week, costs, sanity), encoding="utf-8")
        make_charts(days, per_label_week, run_dir / "charts", log)
        for det in DETECTORS:
            w = week[det]
            log.info("WEEK %-17s detection %s | false alarms %s | precision %s | F1 %.4f", det,
                     pct(w["detection_rate"]), pct(w["false_alarm_rate"]), pct(w["precision"]), w["f1"])
        out.update({"status": "ok", "days": days, "week": week, "per_label_week": per_label_week,
                    "sanity": sanity, "costs": costs})
        log.info("report: %s", run_dir / "WEEK_RESULTS.md")
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    wt.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.0f min)", out["time_taken_s"] / 60)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
