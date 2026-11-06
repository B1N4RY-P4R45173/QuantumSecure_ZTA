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


def test_full_posture_outweighs_both_detectors(tmp_path):
    """A documented WEAKNESS of the current weighting, pinned so a change to
    it is a deliberate decision rather than an accident.

    Posture is worth 60 of 100. Suricata and ML together are worth 40. So a
    fully attested device scores 60 even with a critical C2 signature AND
    every flow classified malicious - above allow-employee-standard's
    threshold of 50, and it keeps its access.

    In other words the detection pipeline, which is the research
    contribution of this project, cannot by itself deny a healthy device.
    Whether that is right is a weighting question, and it is exactly what a
    sensitivity analysis of the trust weights needs to answer. It is
    asserted here so the behaviour is visible rather than surprising.
    """
    s = _open(sid="sid-attested", ip=CLEAN_IP, posture=HEALTHY)

    telemetry = _flagged_telemetry(tmp_path / "telemetry.json", CLEAN_IP)
    controller = PolicyController(telemetry_path=str(telemetry))
    passes, score, _reason = controller._rescore(s, *controller._current_inputs())

    assert score == 60, f"expected 60 (posture 60 + suricata 0 + ml 0), got {score}"
    assert passes, "the weighting changed - re-check the sensitivity analysis"
    assert controller.reevaluate() == []


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
