"""Trust is re-evaluated during a session, not only at admission.

This is the property that separates Zero Trust from authorise-once, and
until these tests existed the Gateway did not have it: a grant was judged
when the knock arrived and never again, so a device that became
untrustworthy kept its access until its lease happened to run out.

Two mechanisms are under test, and they are independent:

  1. The Controller re-scores live sessions against current evidence and
     revokes the ones that now fail. Evidence changes under a running
     session - a detector rewrites the telemetry snapshot, an operator
     tightens policies.yaml.

  2. The proxy re-reads the lease immediately before forwarding, so a
     revoked or expired session cannot be spent on a connection that was
     already open. Checking only at accept left a measurable hole: a client
     could handshake, wait out its lease, then send its request and be
     served with the session table empty.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_GATEWAY = _HERE.parent
_ROOT = _GATEWAY.parent
for _p in (str(_ROOT), str(_GATEWAY)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from controller.policy_controller import PolicyController
from firewall.sessions import TABLE

# A device the IDP attested as fully healthy.
HEALTHY = {
    "device_managed": True, "os_patched": True, "known_device": True,
    "location_expected": True, "disk_encrypted": True, "antivirus_running": True,
}

CLEAN_IP = "10.0.0.21"      # present in telemetry_snapshot.json, no alerts
COMPROMISED_IP = "10.0.0.9"  # present with Suricata alerts incl. critical


@pytest.fixture(autouse=True)
def clean_table():
    for s in list(TABLE.active()):
        TABLE.close(s.session_id, "test setup")
    yield
    for s in list(TABLE.active()):
        TABLE.close(s.session_id, "test teardown")


def _open(sid="sid-x", ip=CLEAN_IP, port=443, posture=None, ttl=300):
    return TABLE.open(session_id=str(uuid.uuid4()), sid=sid, client_ip=ip,
                      access_port=port, protocol="tcp", ttl_seconds=ttl,
                      acl="FULL", hosts=(),
                      posture_signals=HEALTHY if posture is None else posture)


# --------------------------------------------------------------------------- #
# The session carries its posture forward                                     #
# --------------------------------------------------------------------------- #

def test_session_remembers_the_attested_posture():
    """Without this the Controller cannot re-score: posture arrives signed in
    a knock ticket and there is no honest way to re-derive it between knocks."""
    s = _open()
    assert s.posture_signals == HEALTHY
    assert TABLE.active()[0].posture_signals["device_managed"] is True


def test_a_session_opened_without_posture_is_not_invented():
    s = _open(posture={})
    assert s.posture_signals == {}


# --------------------------------------------------------------------------- #
# Re-evaluation                                                               #
# --------------------------------------------------------------------------- #

def test_a_healthy_session_survives_reevaluation():
    """The pass must not be trigger-happy: a session that still passes policy
    keeps its access, or the Gateway would cut everyone every cycle."""
    s = _open(sid="sid-healthy")
    revoked = PolicyController().reevaluate()
    assert revoked == []
    assert any(a.session_id == s.session_id for a in TABLE.active())


def test_reevaluation_with_no_sessions_is_a_no_op():
    assert PolicyController().reevaluate() == []


def test_policy_tightened_under_a_live_session_revokes_it(tmp_path, monkeypatch):
    """An operator tightens the policy while a client is connected. The
    session must not outlive the rule that permitted it."""
    s = _open(sid="sid-tighten")
    assert TABLE.active(), "precondition: a live session"

    # A policy file that denies everything, as a blanket tightening would.
    strict = tmp_path / "policies.yaml"
    strict.write_text(
        "policies:\n"
        "  - id: deny-everything\n"
        "    description: operator lockdown\n"
        "    effect: deny\n"
        "    priority: 9999\n"
        '    when: "true"\n'
    )
    controller = PolicyController(policies_path=str(strict))
    revoked = controller.reevaluate()

    assert s.session_id in revoked, "the tightened policy did not revoke the session"
    assert TABLE.active() == [], "the session outlived the rule that allowed it"


def _flagged_telemetry(path: Path, ip: str) -> Path:
    """Both detectors firing at maximum against one address: a critical
    Suricata signature and every scored flow malicious."""
    path.write_text(json.dumps({
        ip: {
            "suricata": {"alert_count": 6, "max_severity": 1,
                         "severity_label": "critical",
                         "categories": ["A Network Trojan was Detected"],
                         "signatures": ["ET MALWARE Cobalt Strike Beacon Observed"]},
            "ml": {"flow_count": 4, "malicious_flows": 4, "anomaly_rate": 1.0,
                   "top_class": "c2_beacon", "class_counts": {"c2_beacon": 4}},
        }
    }))
    return path


def test_detector_evidence_revokes_a_device_with_partial_posture(tmp_path):
    """The case the detection pipeline exists for: a device is admitted, a
    detector flags it, and the session ends."""
    partial = dict(HEALTHY, device_managed=False, location_expected=False)
    s = _open(sid="sid-flagged", ip=CLEAN_IP, posture=partial)

    telemetry = _flagged_telemetry(tmp_path / "telemetry.json", CLEAN_IP)
    revoked = PolicyController(telemetry_path=str(telemetry)).reevaluate()

    assert s.session_id in revoked, (
        "a flagged device with imperfect posture kept its session")
    assert TABLE.active() == []


def test_a_quarantine_tripwire_beats_perfect_posture(tmp_path):
    """Confirmed compromise denies a device however well it is managed.

    This pins the fix to a real hole. Posture is worth 60 of 100 and the two
    detectors together only 40, so under a pure weighted sum a fully
    attested device scored 60 even with a critical C2 signature AND every
    flow classified malicious. 60 clears allow-employee-standard's
    threshold of 50, so it kept its access: the detection pipeline, which is
    the research contribution of this project, could not by itself deny a
    healthy device.

    The sum was not rebalanced to fix it. Posture answers "is this device
    well configured?" and the detectors answer "is it compromised right
    now?"; no choice of weights stops a confident answer to the first from
    burying the second. Instead trust_scorer raises a disqualifier, and the
    score is forced to 0.

    The component scores must survive in the breakdown: an operator who
    sees only 0 cannot tell a quarantined machine from an unattested one,
    and would "fix" a correctly-configured laptop by re-imaging it.
    """
    s = _open(sid="sid-attested", ip=CLEAN_IP, posture=HEALTHY)

    telemetry = _flagged_telemetry(tmp_path / "telemetry.json", CLEAN_IP)
    controller = PolicyController(telemetry_path=str(telemetry))
    passes, score, reason = controller._rescore(s, *controller._current_inputs())

    assert score == 0, f"a quarantined device must score 0, got {score}"
    assert not passes, "a device with an active C2 beacon kept its access"

    # And the live session is actually torn down, not merely scored badly.
    assert controller.reevaluate() != [], "the compromised session survived review"


def test_quarantine_keeps_the_posture_evidence_visible(tmp_path):
    """The 0 has to be explainable, or the denial gets misdiagnosed."""
    from SDP_CONTROLLER import trust_scorer

    flagged = json.loads((_flagged_telemetry(
        tmp_path / "telemetry.json", CLEAN_IP)).read_text())[CLEAN_IP]
    breakdown = trust_scorer.compute_trust_score(
        HEALTHY, flagged.get("suricata"), flagged.get("ml"))

    assert breakdown.score == 0
    assert breakdown.disqualified, "no reason recorded for the quarantine"
    assert breakdown.posture_score == 60, (
        "posture must stay visible at its real value, not be zeroed too")
    assert any("QUARANTINED" in n for n in breakdown.notes)


def test_a_high_severity_alert_is_scored_not_quarantined(tmp_path):
    """The tripwire stays narrow: only the critical class disqualifies.

    Without this, every medium/high signature becomes a lockout and the
    graded score stops meaning anything.
    """
    from SDP_CONTROLLER import trust_scorer

    high = {"alert_count": 1, "max_severity": 2,
            "signatures": ["ET GEO Traffic from Sanctioned Region"]}
    breakdown = trust_scorer.compute_trust_score(HEALTHY, high, None)

    assert breakdown.disqualified is None
    assert breakdown.score > 0, "a high-severity alert must still be graded"


def test_absent_telemetry_never_quarantines():
    """"We did not look" is not evidence of compromise - it already costs
    half credit on both detectors, which is the correct penalty."""
    from SDP_CONTROLLER import trust_scorer

    breakdown = trust_scorer.compute_trust_score(HEALTHY, None, None)
    assert breakdown.disqualified is None
    assert breakdown.score > 0


def test_an_unreadable_policy_revokes_rather_than_coasting(tmp_path):
    """Fail closed. A Gateway that cannot read its policy has no basis to
    keep anyone connected, and coasting on the last good copy is exactly the
    behaviour an operator replacing a bad rule does not want.

    The file is broken AFTER the Controller starts, which is the real
    sequence: an unreadable file at startup aborts the Gateway outright, so
    the only way to reach this path is for a good file to go bad under a
    running process.
    """
    good = tmp_path / "policies.yaml"
    good.write_text(
        "policies:\n"
        "  - id: allow-all\n"
        "    description: permissive baseline\n"
        "    effect: allow\n"
        "    priority: 1\n"
        '    when: "true"\n'
    )
    controller = PolicyController(policies_path=str(good))
    s = _open(sid="sid-unreadable")

    good.write_text("policies: [[[ not yaml")
    # The reload triggers on an exact mtime comparison, so two writes inside
    # one filesystem timestamp tick look like no change at all. Bumped
    # explicitly here to test the fail-closed path rather than to race the
    # clock. (That the check is mtime-only is a real if minor limitation: a
    # policy edit landing in the same tick as the previous load is missed
    # until the next edit.)
    import os as _os
    stat = _os.stat(good)
    _os.utime(good, (stat.st_atime + 10, stat.st_mtime + 10))

    revoked = controller.reevaluate()

    assert s.session_id in revoked
    assert TABLE.active() == []


def test_revocation_closes_every_session_for_that_identity(tmp_path):
    """Revocation is by sid, so a client holding several grants loses all of
    them - otherwise a compromised device keeps its other open ports."""
    sid = "sid-multi"
    _open(sid=sid, port=443)
    _open(sid=sid, port=8443)
    _open(sid="sid-other", port=443)
    assert len(TABLE.active()) == 3

    strict = tmp_path / "policies.yaml"
    strict.write_text(
        "policies:\n"
        "  - id: deny-everything\n"
        "    description: lockdown\n"
        "    effect: deny\n"
        "    priority: 9999\n"
        '    when: "true"\n'
    )
    PolicyController(policies_path=str(strict)).reevaluate()
    assert TABLE.active() == [], "a revoked identity kept one of its grants"


def test_the_reaper_is_left_to_own_expired_sessions():
    """Re-evaluation must not double-handle a session the reaper will close,
    or the two would race and the logs would show spurious revocations."""
    _open(sid="sid-expired", ttl=-1)
    revoked = PolicyController().reevaluate()
    assert revoked == [], "re-evaluation grabbed a session the reaper owns"


# --------------------------------------------------------------------------- #
# How long stale posture can survive                                          #
# --------------------------------------------------------------------------- #

def test_posture_cannot_outlive_its_lease():
    """Bounds the one gap re-evaluation genuinely cannot close.

    Posture arrives signed inside a knock ticket, so it cannot honestly be
    re-derived between knocks - a live session is re-scored against its
    admission-time posture. The open question is how long a device whose
    posture has since decayed can keep trading on the old value.

    The answer is one lease, because nothing renews a lease. expires_at is
    set once in open() and there is no extend/renew/touch path, so holding
    access past the TTL takes a brand-new knock, which takes a brand-new
    attested ticket. That is the structural reason the gap is bounded by the
    TTL rather than unbounded, and it is worth a test because the bound is a
    property of what the code does NOT have - it would be lost silently the
    day somebody adds session renewal as a convenience.
    """
    import inspect

    from firewall import sessions as sessions_mod

    s = _open(sid="sid-lease", ip=CLEAN_IP, posture=HEALTHY, ttl=300)
    try:
        before = s.expires_at

        # Re-scoring a session must never push its deadline out.
        PolicyController().reevaluate()
        assert s.expires_at == before, "re-evaluation extended the lease"

        # And no API exists to extend it.
        for name in ("extend", "renew", "touch", "refresh"):
            assert not hasattr(TABLE, name), (
                f"SessionTable.{name}() would let posture outlive its "
                f"attestation - re-check the re-evaluation argument")

        # expires_at is assigned exactly once, at open().
        src = inspect.getsource(sessions_mod)
        writes = src.count("expires_at=") + src.count("expires_at =")
        assert writes == 1, (
            f"expires_at is written in {writes} places; a lease may now be "
            f"renewable, which would unbound the posture gap")
    finally:
        TABLE.close(s.session_id, "test teardown")
