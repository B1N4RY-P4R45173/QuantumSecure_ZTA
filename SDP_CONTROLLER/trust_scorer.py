"""
Trust Score Calculator
----------------------
Fuses three sources of evidence into a 0..100 trust score:

  * Device posture   (60 pts)   — MDM signals: managed, patched, encrypted, ...
  * Suricata IDS     (25 pts)   — signature-based alerts on the device's flows
  * ML anomaly       (15 pts)   — RandomForest classifier over flow features

Interface: `enrich_request(request, telemetry=None)`
  * `request` is the ZT access request (as in scenarios.yaml).
  * `telemetry` is an optional per-device network snapshot produced by the
    detection pipeline. If absent, we fall back to the request's static
    `device.signals` (baseline zero-trust: unknown = untrusted).

Score contributions are always transparent — the breakdown is attached to
`device.trust_breakdown` so operators can explain any decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Weights (must sum to 100)
# ---------------------------------------------------------------------------

POSTURE_WEIGHTS = {
    "device_managed":     15,
    "disk_encrypted":      5,
    "os_patched":         15,
    "antivirus_running":   5,
    "known_device":       10,
    "location_expected":  10,
}
POSTURE_MAX = sum(POSTURE_WEIGHTS.values())      # 60

SURICATA_MAX = 25
ML_MAX = 15
TOTAL_MAX = POSTURE_MAX + SURICATA_MAX + ML_MAX  # 100
assert TOTAL_MAX == 100


# ---------------------------------------------------------------------------
# Quarantine tripwires
# ---------------------------------------------------------------------------
# Posture and the detectors answer two different questions. Posture asks
# "is this device well configured?" — managed, patched, encrypted. The
# detectors ask "is this device behaving like it is compromised right now?"
# A weighted sum lets a good answer to the first bury a bad answer to the
# second: a fully attested laptop scores 60/60 on posture, and 60 clears
# both the block bar (40) and the internal-access bar (50) even with both
# detectors at zero. A managed device running a Cobalt Strike beacon kept
# its access.
#
# Confirmed-compromise evidence is therefore a disqualifier, not a
# deduction. A device that trips either wire below scores 0 and is denied
# regardless of how well it is managed, which is also what a real
# quarantine does — being well patched is not a defence against already
# being owned.
#
# Deliberately narrow, because the cost of a false positive here is a
# locked-out user, not a smaller grant:
#   * Suricata severity 1 is the "critical" class, and the signatures that
#     carry it (ET MALWARE, network-trojan) assert an active infection
#     rather than reconnaissance against the host.
#   * The ML wire needs a MAJORITY of observed flows classified malicious,
#     so a single misclassified flow cannot quarantine a device. A rate
#     this high is a sustained pattern, not a blip.
CRITICAL_SEVERITY = 1
ML_QUARANTINE_RATE = 0.5

# The second ML wire, and the one with research behind it. The PC 2 quarantine
# sweep (runs/edge_inline_eval_20261104_164043) swept minimum hits 1/2/3/5/8
# against windows of 30-600s and settled on TWO qualifying rows, where a row
# qualifies only if the classifier is at least 0.9 confident AND the
# autoencoder independently calls it unlike normal. Requiring both detectors
# to agree is what took the share of normal sensor traffic wrongly blocked
# from 3.8% down to 0.50%.
#
# It earns its place beside the rate because the two catch different things.
# On the verification fixture a rate of 50% never fires for Scan / Recon
# (only 28% of those rows are labelled an attack - stealthy scans look close
# to normal), yet they still produce 17 quarantine-grade hits. Conversely a
# flood is caught by either. Normal traffic produces neither: 0% labelled,
# 0 hits.
ML_QUARANTINE_HITS = 2


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class TrustBreakdown:
    score: int
    posture_score: int
    suricata_score: int
    ml_score: int
    contributions: dict[str, Any]
    notes: list[str]
    # None when nothing tripped; otherwise why the device is quarantined.
    disqualified: str | None = None


def _posture_score(signals: dict) -> tuple[int, dict[str, int]]:
    contrib: dict[str, int] = {}
    total = 0
    for name, weight in POSTURE_WEIGHTS.items():
        val = signals.get(name)
        pts = weight if val is True else 0
        contrib[name] = pts
        total += pts
    return total, contrib


def _suricata_score(alerts: dict | None) -> tuple[int, str]:
    """
    Real Suricata severity: 1=critical, 2=high, 3=medium.
    Score is subtracted from SURICATA_MAX. Any critical → 0.
    """
    if alerts is None:
        # No telemetry available: give benefit of the doubt at half credit.
        return SURICATA_MAX // 2, "no telemetry, half-credit"
    count = alerts.get("alert_count", 0)
    if count == 0:
        return SURICATA_MAX, "no alerts"
    max_sev = alerts.get("max_severity", 3) or 3
    if max_sev <= 1:
        return 0, f"{count} alert(s) incl. critical"
    if max_sev == 2:
        # High severity: 4 pts, minus 2 per extra alert, floor 0
        return max(0, 8 - 2 * count), f"{count} high-severity alert(s)"
    # Medium severity only
    return max(0, SURICATA_MAX - 3 * count), f"{count} medium-severity alert(s)"


def _ml_score(ml_summary: dict | None) -> tuple[int, str]:
    """
    ML anomaly_rate ∈ [0,1]. 0 → full credit, 1 → zero.
    Linear penalty; heavier if any malicious class other than benign top-hits.
    """
    if ml_summary is None:
        return ML_MAX // 2, "no telemetry, half-credit"
    rate = ml_summary.get("anomaly_rate", 0.0) or 0.0
    top = ml_summary.get("top_class", "benign")
    pts = int(round(ML_MAX * (1.0 - rate)))
    note = f"anomaly_rate={rate:.2f}, top={top}"
    # Extra hit for known-bad top classes (C2 / DoS)
    if top in {"c2_beacon", "dos"}:
        pts = max(0, pts - 5)
        note += " (severe class → -5)"
    return pts, note


def _disqualifier(suricata: dict | None, ml: dict | None) -> str | None:
    """Name the tripwire this evidence crosses, or None.

    Absent telemetry never disqualifies: "we did not look" is not evidence
    of compromise. It already costs half credit on both detectors, which is
    the right penalty for not knowing.
    """
    if suricata:
        count = suricata.get("alert_count", 0) or 0
        sev = suricata.get("max_severity")
        if count and sev is not None and sev <= CRITICAL_SEVERITY:
            sigs = suricata.get("signatures") or []
            which = f": {sigs[0]}" if sigs else ""
            return f"critical IDS signature{which}"

    if ml:
        flows = ml.get("flow_count", 0) or 0
        top = ml.get("top_class", "unknown")

        # Both detectors agreeing on a couple of rows is stronger evidence
        # than a large share of weakly-flagged ones, so it is checked first
        # and names itself in the reason.
        hits = ml.get("quarantine_hits", 0) or 0
        if flows and hits >= ML_QUARANTINE_HITS:
            return (f"{hits} flow(s) of {flows} met the quarantine rule "
                    f"(classifier >= 0.9 and autoencoder agreeing, top={top})")

        rate = ml.get("anomaly_rate", 0.0) or 0.0
        if flows and rate >= ML_QUARANTINE_RATE:
            return (f"{rate:.0%} of {flows} observed flow(s) classified "
                    f"malicious (top={top})")

    return None


def compute_trust_score(
    signals: dict | None = None,
    suricata: dict | None = None,
    ml: dict | None = None,
) -> TrustBreakdown:
    signals = signals or {}
    p_score, p_contrib = _posture_score(signals)
    s_score, s_note = _suricata_score(suricata)
    m_score, m_note = _ml_score(ml)

    total = min(TOTAL_MAX, p_score + s_score + m_score)
    notes = [
        f"posture:  {p_score}/{POSTURE_MAX}",
        f"suricata: {s_score}/{SURICATA_MAX}   ({s_note})",
        f"ml:       {m_score}/{ML_MAX}   ({m_note})",
    ]

    # A tripwire overrides the sum rather than adjusting it. The component
    # scores stay in the notes on purpose: an operator needs to see that
    # posture was perfect AND that the device was quarantined anyway, or the
    # denial looks like a posture failure and gets "fixed" by re-imaging a
    # machine that was never misconfigured.
    disqualified = _disqualifier(suricata, ml)
    if disqualified is not None:
        notes.append(f"QUARANTINED: {disqualified} - score forced to 0 "
                     f"(was {total}/{TOTAL_MAX})")
        total = 0
    contrib = {
        "posture": p_contrib,
        "suricata": {"score": s_score, "raw": suricata},
        "ml": {"score": m_score, "raw": ml},
    }
    return TrustBreakdown(total, p_score, s_score, m_score, contrib, notes,
                          disqualified)


# ---------------------------------------------------------------------------
# Telemetry snapshot (produced by run_pipeline.py)
# ---------------------------------------------------------------------------

def load_telemetry(path: str | Path) -> dict[str, dict]:
    """
    Snapshot shape:
      { "10.0.0.9": {"suricata": {...}, "ml": {...}}, ... }
    """
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Request enrichment
# ---------------------------------------------------------------------------

def enrich_request(request: dict, telemetry: dict[str, dict] | None = None) -> dict:
    """
    Attach a computed trust score to the request's device block.
      * If `device.trust_score` is explicitly set, respect it (test overrides).
      * Otherwise fuse posture + telemetry-derived Suricata/ML signals.
    """
    device = dict(request.get("device") or {})
    if "trust_score" in device:
        return request

    signals = device.get("signals") or {}
    telem_entry = None
    if telemetry:
        ip = (request.get("context") or {}).get("ip")
        if ip and ip in telemetry:
            telem_entry = telemetry[ip]

    # If telemetry has an entry for this device, treat missing sub-signals as
    # "the pipeline ran and saw nothing bad" (full credit), not "unknown" (half).
    if telem_entry is not None:
        suricata_info = telem_entry.get("suricata") or {"alert_count": 0}
        ml_info = telem_entry.get("ml") or {"anomaly_rate": 0.0, "top_class": "benign"}
    else:
        suricata_info = None
        ml_info = None

    # Fallback: if no telemetry snapshot, honor the boolean signals in the request
    # so scenarios still run standalone.
    if telem_entry is None:
        if "no_suricata_alerts" in signals:
            suricata_info = {"alert_count": 0} if signals["no_suricata_alerts"] else \
                            {"alert_count": 3, "max_severity": 2}
        if "ml_anomaly_score_ok" in signals:
            ml_info = {"anomaly_rate": 0.0, "top_class": "benign"} if signals["ml_anomaly_score_ok"] else \
                      {"anomaly_rate": 0.9, "top_class": "port_scan"}

    breakdown = compute_trust_score(signals, suricata_info, ml_info)

    device["trust_score"] = breakdown.score
    device["trust_breakdown"] = {
        "posture":  breakdown.posture_score,
        "suricata": breakdown.suricata_score,
        "ml":       breakdown.ml_score,
        "notes":    breakdown.notes,
        "detail":   breakdown.contributions,
        # Carried separately from the score so a caller can say WHY a
        # quarantined device was denied. A bare 0 is indistinguishable from
        # a device with no posture at all.
        "disqualified": breakdown.disqualified,
    }
    new_req = dict(request)
    new_req["device"] = device
    return new_req
