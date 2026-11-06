"""
The same metrics for every model (and for Suricata), saved as results/<MODEL>.json.

Detection
  * multiclass: accuracy, macro F1, per-class precision / recall / F1
  * binary (attack vs benign): precision, recall (= detection rate), F1, FPR
  * per attack class: detection rate = share of its flows NOT predicted as Benign
Time to detect
  * for each attack burst: how many attack flows passed before the first alert
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_recall_fscore_support)

from common import config as C

BENIGN_ID = C.CLASS_TO_ID[C.BENIGN]


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    t = y_true != BENIGN_ID
    p = y_pred != BENIGN_ID
    tp = int((t & p).sum()); fp = int((~t & p).sum())
    fn = int((t & ~p).sum()); tn = int((~t & ~p).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": prec,
        "recall_detection_rate": rec,
        "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def time_to_detect(y_pred: np.ndarray, burst: np.ndarray) -> dict:
    """Attack flows that passed before the first alert, per burst."""
    m = burst >= 0
    df = pd.DataFrame({"burst": burst[m], "flag": y_pred[m] != BENIGN_ID})
    df["rank"] = df.groupby("burst").cumcount()
    first = df[df["flag"]].groupby("burst")["rank"].min()
    n_bursts = int(df["burst"].nunique())
    return {
        "bursts": n_bursts,
        "bursts_detected_share": len(first) / n_bursts if n_bursts else 0.0,
        "median_attack_flows_before_alert": float(first.median()) if len(first) else None,
        "p90_attack_flows_before_alert": float(first.quantile(0.9)) if len(first) else None,
    }


def evaluate(y_true: np.ndarray, y_pred: np.ndarray, burst: np.ndarray | None = None) -> dict:
    labels = list(range(len(C.CLASSES)))
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    present = s > 0
    per_class = {}
    for i, c in enumerate(C.CLASSES):
        if not present[i]:
            continue
        mask = y_true == i
        per_class[c] = {
            "precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i]),
            "detection_rate": float((y_pred[mask] != BENIGN_ID).mean()) if c != C.BENIGN else None,
        }
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=np.where(present)[0], average="macro", zero_division=0)),
        "binary": binary_metrics(y_true, y_pred),
        "per_class": per_class,
        "confusion_matrix": {
            "labels": [C.CLASSES[i] for i in np.where(present)[0]],
            "matrix": confusion_matrix(y_true, y_pred, labels=np.where(present)[0]).tolist(),
        },
    }
    if burst is not None:
        out["time_to_detect"] = time_to_detect(y_pred, burst)
    return out


def text_report(name: str, y_true: np.ndarray, y_pred: np.ndarray, res: dict) -> str:
    present = sorted(set(y_true.tolist()))
    b = res["binary"]
    lines = [
        f"model: {name}",
        f"accuracy:   {res['accuracy']:.4f}",
        f"macro F1:   {res['macro_f1']:.4f}",
        f"binary  ->  precision {b['precision']:.4f}  detection rate {b['recall_detection_rate']:.4f}"
        f"  F1 {b['f1']:.4f}  FPR {b['false_positive_rate']:.5f}",
    ]
    if "time_to_detect" in res:
        t = res["time_to_detect"]
        lines.append(f"time to detect -> bursts detected {t['bursts_detected_share']:.3f}, "
                     f"median attack flows before alert {t['median_attack_flows_before_alert']}")
    lines += ["", classification_report(y_true, y_pred, labels=present,
                                        target_names=[C.CLASSES[i] for i in present],
                                        digits=4, zero_division=0)]
    return "\n".join(lines)


def save_result(name: str, result: dict) -> None:
    C.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    result = {"model": name, "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              **result}
    path = C.RESULTS_DIR / f"{name}.json"
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"saved: {path}")
