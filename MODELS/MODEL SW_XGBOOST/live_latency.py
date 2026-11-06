"""
LIVE latency test: can each model keep up with the gateway WITHOUT dropping flows?

    python "MODELS/MODEL SW_XGBOOST/live_latency.py"
    python "MODELS/MODEL SW_XGBOOST/live_latency.py" --buffer-flows 512 --rates 2000 5000 10000

For every trained model in the balanced runs (FLAT, SW_W16, BAL_W16, BAL_MS, ENS; LightGBM and
XGBoost), with ONE CPU thread, one flow at a time:

  1. Equivalence: the fast live feature builder (common/live_windows.py) must give the same
     inputs as the training code (build_X). Reports max difference and prediction agreement.
  2. Latency per flow, split into PREPROCESSING (window statistics + deviation) and MODEL.
  3. Gateway queue: flows arrive at R flows/s (Poisson) into a buffer of B flows; the detector
     serves them one by one with the measured times. A flow that finds the buffer full is
     DROPPED (not inspected). Reports the drop rate per arrival rate and the highest rate with
     at most --max-drop drops.
  4. Choice: for each arrival rate, the model with the best VALIDATION balance score whose
     drop rate stays within --max-drop.

Saves: runs/live_latency_<YYYYMMDD_HHMMSS>/
       run.log, config.json, results.json, LIVE_LATENCY.md, charts/*.png
"""

from __future__ import annotations

import os

# one CPU thread for everything, like a small gateway (must be set before numpy is imported)
for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[_v] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = ""

import argparse                                                            # noqa: E402
import json                                                                # noqa: E402
import sys                                                                 # noqa: E402
import time                                                                # noqa: E402
import traceback                                                           # noqa: E402
from collections import deque                                              # noqa: E402
from datetime import datetime                                              # noqa: E402
from pathlib import Path                                                   # noqa: E402

import numpy as np                                                         # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import window_tradeoff as wt                                               # noqa: E402
from train_balanced import build_X, combine                                # noqa: E402

# ---------------------------------------------------------------- settings
PROJECT_ROOT = wt.PROJECT_ROOT
RUNS_DIR = wt.RUNS_DIR
SCRIPT_NAME = "live_latency"
DEFAULT_RUN_DIRS = ["runs/sw_lgbm_balanced_20261031_005302", "runs/sw_xgb_balanced_20261031_000650"]
MODEL_NAMES = ["FLAT", "SW_W16", "BAL_W16", "BAL_MS", "ENS"]
N_CHECK = 3_000          # flows used for the equivalence check
N_TIMED = 5_000          # flows timed one by one
WARMUP = 200
BUFFER_FLOWS = 1_024     # gateway buffer, in flows waiting for the detector
MAX_DROP = 0.001         # at most 0.1% of flows may be dropped
SIM_ARRIVALS = 100_000
RATES = [1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000]
AGREE_MIN = 0.999        # live builder must agree with the training code on >= 99.9% of predictions
CHART_FILES = ["01_latency_breakdown.png", "02_drop_rate_vs_arrival_rate.png"]


# ---------------------------------------------------------------- models
def single_thread_predictor(model_dir: Path, info: dict):
    """predict_proba for a small batch, 1 thread, no sklearn wrapper overhead."""
    path = str(model_dir / info["model_file"])
    if info["algo"] == "lightgbm":
        import lightgbm as lgb
        b = lgb.Booster(model_file=path)
        return lambda X: b.predict(X, num_threads=1)
    import xgboost as xgb
    b = xgb.Booster()
    b.load_model(path)
    b.set_param({"nthread": 1, "device": "cpu"})
    return lambda X: np.asarray(b.inplace_predict(X)).reshape(len(X), -1)


def load_run_models(run_dir: Path) -> list[dict]:
    from common import config as C
    res = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    algo = res.get("algo", "xgboost")
    short = wt.NAMES[algo]["short"]
    base = {}
    for name in MODEL_NAMES[:-1]:
        d = run_dir / "models" / name
        info = json.loads((d / "model_info.json").read_text(encoding="utf-8"))
        info.setdefault("algo", algo)
        base[name] = {"dir": d, "info": info, "predict": single_thread_predictor(d, info),
                      "ids": np.array([C.CLASS_TO_ID[c] for c in info["classes"]])}
    out = []
    for name in MODEL_NAMES:
        r = res["models"].get(name, {})
        entry = {"label": f"{short} {name}", "algo": algo, "name": name, "run": run_dir.name,
                 "val_balance": wt.g(r, "val.balance_score"),
                 "test": {k: wt.g(r, f"test_original.{p}") for k, p in [
                     ("hidden", "hidden_detection"), ("start", "start_detection"),
                     ("single_right", "point_right_class"), ("series_right", "series_right_class"),
                     ("false_alarms", "binary.false_positive_rate"), ("balance", "balance_score")]},
                 "old_pandas_latency_ms": wt.g(r, "live.latency_ms_median"),
                 "live_ram_mb": wt.g(r, "live.live_peak_ram_mb")}
        if name == "ENS":
            ens = json.loads((run_dir / "models" / "ENS" / "ensemble.json").read_text(encoding="utf-8"))
            entry.update({"members": [base[m] for m in ens["members"]], "threshold": ens["threshold"],
                          "spec": base[ens["members"][0]]["info"]["spec"]})
        else:
            entry.update({"members": [base[name]], "threshold": None, "spec": base[name]["info"]["spec"]})
        entry["feats"] = entry["members"][0]["info"]["base_features"]      # 70, or 64 without bulk
        entry["label"] += " (no bulk)" if len(entry["feats"]) < 70 else ""
        out.append(entry)
    return out


def classify(entry: dict, row: np.ndarray, raw: np.ndarray) -> int:
    """Class id for one flow. ENS: BAL decides, FLAT may add an alert (same rule as train_balanced)."""
    m0 = entry["members"][0]
    p0 = m0["predict"](row[None, :])
    if len(entry["members"]) == 1:
        return int(m0["ids"][p0.argmax(1)[0]])
    m1 = entry["members"][1]
    p1 = m1["predict"](raw[None, :])
    return int(combine(p0, m0["ids"], p1, m1["ids"], entry["threshold"])[0])


# ---------------------------------------------------------------- tests
def equivalence(entry: dict, flows: np.ndarray, feats: list[str]) -> dict:
    """Live builder vs training code (build_X) on the same flows."""
    import pandas as pd
    from common.live_windows import LiveFeatureBuilder
    spec = entry["spec"]
    S = max(spec["windows"] + [1]) - 1
    df = pd.DataFrame(flows, columns=feats)
    ref = build_X(df, feats, spec, S)
    b = LiveFeatureBuilder(feats, spec["windows"], spec["dev"])
    live = [b.push(x) for x in flows]
    live = np.stack([r for r in live if r is not None])
    n = min(len(ref), len(live))
    ref, live = ref[:n].astype(np.float64), live[:n].astype(np.float64)
    diff = np.abs(ref - live)
    rel = diff / (np.abs(ref) + 1.0)
    m = entry["members"][0]
    agree = float((m["predict"](ref).argmax(1) == m["predict"](live).argmax(1)).mean())
    return {"rows": int(n), "n_features": int(ref.shape[1]), "max_abs_diff": float(diff.max()),
            "max_rel_diff": float(rel.max()), "prediction_agreement": agree}


def time_one_by_one(entry: dict, flows: np.ndarray, feats: list[str]) -> dict:
    from common.live_windows import LiveFeatureBuilder
    spec = entry["spec"]
    b = LiveFeatureBuilder(feats, spec["windows"], spec["dev"])
    pre, model = [], []
    for k, x in enumerate(flows):
        t0 = time.perf_counter()
        row = b.push(x)
        t1 = time.perf_counter()
        if row is None:
            continue
        classify(entry, row, x)
        t2 = time.perf_counter()
        if k >= WARMUP:
            pre.append(t1 - t0)
            model.append(t2 - t1)
    pre, model = np.array(pre), np.array(model)
    total = pre + model

    def us(a, q):
        return float(np.percentile(a, q) * 1e6)

    return {"timed_flows": int(len(total)),
            "pre_us_median": us(pre, 50), "model_us_median": us(model, 50),
            "total_us_median": us(total, 50), "total_us_p95": us(total, 95), "total_us_p99": us(total, 99),
            "total_us_mean": float(total.mean() * 1e6), "service_s": total}


def simulate(service_s: np.ndarray, rate: float, buffer: int, n: int, seed: int) -> dict:
    """FIFO queue, Poisson arrivals, one detector, room for `buffer` flows (incl. the one in service)."""
    rng = np.random.default_rng(seed)
    arrive = np.cumsum(rng.exponential(1.0 / rate, n))
    svc = rng.choice(service_s, n)
    in_system: deque = deque()
    last_done, drops, waits = 0.0, 0, []
    for a, s in zip(arrive, svc):
        while in_system and in_system[0] <= a:
            in_system.popleft()
        if len(in_system) >= buffer:
            drops += 1
            continue
        start = max(a, last_done)
        waits.append(start - a)
        last_done = start + s
        in_system.append(last_done)
    w = np.array(waits) if waits else np.zeros(1)
    return {"drop_rate": drops / n, "wait_ms_median": float(np.median(w) * 1e3),
            "wait_ms_p99": float(np.percentile(w, 99) * 1e3)}


def max_rate(service_s: np.ndarray, buffer: int, max_drop: float, n: int) -> float:
    lo, hi = 1.0, 2.0 / service_s.mean()
    for _ in range(18):
        mid = (lo + hi) / 2
        if simulate(service_s, mid, buffer, n, seed=7)["drop_rate"] <= max_drop:
            lo = mid
        else:
            hi = mid
    return lo


# ---------------------------------------------------------------- report
def report(entries: list[dict], choice: dict, args, avg_pkts: float) -> str:
    f = wt.fmt
    L = ["# Live latency and gateway drops (1 CPU thread, one flow at a time)", "",
         f"Gateway buffer: **{args.buffer_flows:,} flows**. Allowed drops: **{100 * args.max_drop:.2f}%**. "
         f"Packets/s = flows/s × {avg_pkts:.2f}. CICFlowMeter time is NOT included.", "",
         "## 1. Is the fast live builder identical to the training code?", "",
         "| Model | Features | Max abs diff | Max rel diff | Same prediction |", "|---|---|---|---|---|"]
    for e in entries:
        q = e["equivalence"]
        ok = "✅" if q["prediction_agreement"] >= AGREE_MIN else "⚠"
        L.append(f"| {e['label']} | {q['n_features']} | {q['max_abs_diff']:.3g} | {q['max_rel_diff']:.3g} "
                 f"| {ok} {100 * q['prediction_agreement']:.2f}% |")
    L += ["", "## 2. Latency per flow (microseconds)", "",
          "| Model | Preprocessing | Model | Total median | p95 | p99 | Old pandas latency | Max flows/s "
          f"(≤ {100 * args.max_drop:.1f}% drops) | Max packets/s |",
          "|---|---|---|---|---|---|---|---|---|"]
    for e in entries:
        t = e["timing"]
        L.append(f"| {e['label']} | {t['pre_us_median']:.0f} | {t['model_us_median']:.0f} | {t['total_us_median']:.0f} "
                 f"| {t['total_us_p95']:.0f} | {t['total_us_p99']:.0f} "
                 f"| {f(e['old_pandas_latency_ms'] * 1000 if e['old_pandas_latency_ms'] else None, 'f0')} "
                 f"| {e['max_flows_per_s']:,.0f} | {e['max_flows_per_s'] * avg_pkts:,.0f} |")
    L += ["", "## 3. Dropped flows at each arrival rate", "",
          "| Model | " + " | ".join(f"{r:,} flows/s" for r in args.rates) + " |", "|---|" + "---|" * len(args.rates)]
    for e in entries:
        L.append(f"| {e['label']} | " + " | ".join(f(e["drops"][str(r)]["drop_rate"], "pct") for r in args.rates) + " |")
    L += ["", "## 4. Best model that keeps up (chosen by VALIDATION balance score)", "",
          "| Arrival rate | Packets/s | Best model | Val balance | Test: hidden single | Test: time-series right "
          "| Test: false alarms |", "|---|---|---|---|---|---|---|"]
    for r in args.rates:
        c = choice[str(r)]
        if c is None:
            L.append(f"| {r:,} | {r * avg_pkts:,.0f} | none keeps up | – | – | – | – |")
            continue
        e = next(x for x in entries if x["label"] == c)
        L.append(f"| {r:,} | {r * avg_pkts:,.0f} | **{c}** | {f(e['val_balance'], 'pct')} | {f(e['test']['hidden'], 'pct')} "
                 f"| {f(e['test']['series_right'], 'pct')} | {f(e['test']['false_alarms'], 'pct')} |")
    L += ["", "## 5. Charts", ""] + [f"![{c}](charts/{c})" for c in CHART_FILES]
    L += ["", "## Notes", "",
          "- Detection numbers come from the balanced runs; the models are the same files, only the feature code is faster.",
          "- A model is only usable if the live builder agrees with the training code (section 1).",
          "- Poisson arrivals. Real traffic is burstier (a DDoS sends many flows at once), so leave headroom: "
          "plan for at most about 50-70% of the max rate.",
          "- A dropped flow is not inspected. If the detector runs inline it can also mean dropped packets; "
          "running it out-of-band (on a copy of the flow records) avoids that."]
    return "\n".join(L) + "\n"


def make_charts(entries: list[dict], args, out_dir: Path, log) -> None:
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
        "axes.edgecolor": wt.GRID, "axes.grid": True, "grid.color": wt.GRID,
        "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True,
        "text.color": wt.INK, "axes.labelcolor": wt.INK2, "xtick.color": wt.INK2, "ytick.color": wt.INK2,
        "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold", "legend.frameon": False,
    })
    labels = [e["label"] for e in entries]
    pre = [e["timing"]["pre_us_median"] for e in entries]
    mod = [e["timing"]["model_us_median"] for e in entries]
    fig, ax = plt.subplots(figsize=(10, 0.45 * len(entries) + 1.6))
    y = np.arange(len(entries))
    ax.barh(y, pre, color=wt.SLOT[0], height=0.6, label="Preprocessing (windows + deviation)")
    ax.barh(y, mod, left=pre, color=wt.SLOT[1], height=0.6, label="Model")
    for i, (p, m) in enumerate(zip(pre, mod)):
        ax.text(p + m, i, f"  {p + m:.0f} µs", va="center", fontsize=8, color=wt.INK)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Median time per flow, 1 CPU thread (µs, lower is better)")
    ax.set_title("Where the time goes per flow (live builder)", loc="left")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out_dir / CHART_FILES[0], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[0])

    # at most 8 series (fixed palette order): all LightGBM models + the two main XGBoost ones
    shown = ([e for e in entries if e["algo"] == "lightgbm"]
             + [e for e in entries if e["algo"] == "xgboost" and e["name"] in ("SW_W16", "BAL_MS")])[:8]
    palette = wt.SLOT + ["#e87ba4", "#008300", "#6250d6", "#e34948"]
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, e in enumerate(shown):
        ax.plot(args.rates, [e["drops"][str(r)]["drop_rate"] for r in args.rates], color=palette[i], lw=2,
                marker="o", ms=6, markeredgecolor=wt.SURFACE, markeredgewidth=1.5, label=e["label"])
    ax.axhline(args.max_drop, color=wt.INK2, lw=1, ls=":")
    ax.text(args.rates[0], args.max_drop, f"  allowed drops {100 * args.max_drop:.1f}%", va="bottom",
            fontsize=8, color=wt.INK2)
    ax.set_xscale("log")
    ax.set_xticks(args.rates, [f"{r:,}" for r in args.rates])
    ax.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
    ax.set_xlabel("Flows arriving per second (log scale)")
    ax.set_ylabel("Flows dropped (lower is better)")
    ax.set_title(f"Gateway drops with a {args.buffer_flows:,}-flow buffer, 1 CPU thread", loc="left")
    ax.legend(loc="upper left", ncol=2)
    fig.tight_layout()
    fig.savefig(out_dir / CHART_FILES[1], dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("chart saved: %s", out_dir / CHART_FILES[1])


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="live latency + gateway drop test")
    ap.add_argument("--runs", nargs="+", default=DEFAULT_RUN_DIRS, help="balanced run folders")
    ap.add_argument("--buffer-flows", type=int, default=BUFFER_FLOWS)
    ap.add_argument("--max-drop", type=float, default=MAX_DROP)
    ap.add_argument("--rates", type=int, nargs="+", default=RATES)
    args = ap.parse_args()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    log = wt.setup_logging(run_dir)
    t_start = time.time()
    out: dict = {"status": "error", "run_dir": str(run_dir)}
    entries: list[dict] = []
    try:
        np.random.seed(42)
        from common.data import load_meta, load_split
        env = wt.log_environment(log)
        meta = load_meta()
        feats = meta["features"]
        avg_pkts = meta["avg_packets_per_flow_test"]
        config = {"script": SCRIPT_NAME, "runs": args.runs, "buffer_flows": args.buffer_flows,
                  "max_drop": args.max_drop, "rates": args.rates, "n_check": N_CHECK, "n_timed": N_TIMED,
                  "warmup": WARMUP, "sim_arrivals": SIM_ARRIVALS, "threads": 1, "environment": env}
        wt.write_json(run_dir / "config.json", config)
        log.info("settings: buffer %d flows, max drop %.3f%%, rates %s, 1 CPU thread",
                 args.buffer_flows, 100 * args.max_drop, args.rates)

        test = load_split("test")[feats].to_numpy(np.float32)
        check_flows, timed_flows = test[:N_CHECK], test[N_CHECK:N_CHECK + N_TIMED + WARMUP]
        del test

        for rd in args.runs:
            run_path = (PROJECT_ROOT / rd).resolve()
            log.info("loading models from %s", run_path)
            for e in load_run_models(run_path):
                cols = [feats.index(f) for f in e["feats"]]
                e["equivalence"] = equivalence(e, check_flows[:, cols], e["feats"])
                t = time_one_by_one(e, timed_flows[:, cols], e["feats"])
                svc = t.pop("service_s")
                e["timing"] = t
                e["max_flows_per_s"] = max_rate(svc, args.buffer_flows, args.max_drop, SIM_ARRIVALS)
                e["drops"] = {str(r): simulate(svc, r, args.buffer_flows, SIM_ARRIVALS, seed=1) for r in args.rates}
                q = e["equivalence"]
                log.info("%-12s same prediction %.2f%% | pre %5.0f µs + model %5.0f µs = %5.0f µs (p99 %5.0f) "
                         "| old pandas %s µs | max %s flows/s",
                         e["label"], 100 * q["prediction_agreement"], t["pre_us_median"], t["model_us_median"],
                         t["total_us_median"], t["total_us_p99"],
                         wt.fmt(e["old_pandas_latency_ms"] * 1000 if e["old_pandas_latency_ms"] else None, "f0"),
                         f"{e['max_flows_per_s']:,.0f}")
                e.pop("members")                     # model objects are not saved (FLAT is shared with ENS)
                e["n_base_features"] = len(e.pop("feats"))
                entries.append(e)

        choice = {}
        for r in args.rates:
            ok = [e for e in entries if e["drops"][str(r)]["drop_rate"] <= args.max_drop
                  and e["equivalence"]["prediction_agreement"] >= AGREE_MIN and e["val_balance"] is not None]
            choice[str(r)] = max(ok, key=lambda e: e["val_balance"])["label"] if ok else None
            log.info("at %s flows/s: best model that keeps up = %s", f"{r:,}", choice[str(r)])
        (run_dir / "LIVE_LATENCY.md").write_text(report(entries, choice, args, avg_pkts), encoding="utf-8")
        make_charts(entries, args, run_dir / "charts", log)
        out.update({"status": "ok", "choice_per_rate": choice})
        log.info("report: %s", run_dir / "LIVE_LATENCY.md")
    except BaseException:
        out["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", out["error"])

    out["time_taken_s"] = round(time.time() - t_start, 1)
    out["models"] = [{k: (str(v) if isinstance(v, Path) else v) for k, v in e.items()} for e in entries]
    wt.write_json(run_dir / "results.json", out)
    if out["status"] == "ok":
        log.info("FINISHED OK (%.0f s)", out["time_taken_s"])
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
