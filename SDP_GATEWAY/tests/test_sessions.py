"""The Gateway's session table: leases, revocation and the reaper.

Every test runs against a fresh SessionTable rather than the module-level
TABLE, so they do not interfere with each other or leak state between runs.
The firewall calls underneath are in dry-run (conftest sets
GATEWAY_FORCE_DRY_RUN), so nothing reaches the kernel; what is under test is
the bookkeeping that decides when a rule goes in and comes out.
"""

from __future__ import annotations

import time

import pytest

from firewall.sessions import SessionTable


@pytest.fixture
def table():
    t = SessionTable()
    yield t
    t.stop()


def _open(table, *, session_id="s-1", sid="sid-alice", port=22, ttl=30,
          acl="FULL", hosts=()):
    return table.open(session_id=session_id, sid=sid, client_ip="10.0.0.9",
                      access_port=port, protocol="tcp", ttl_seconds=ttl,
                      acl=acl, hosts=hosts)


def test_open_records_the_lease(table):
    session = _open(table)
    assert len(table) == 1
    assert session.acl == "FULL"
    assert session.hosts == ()
    assert not session.expired
    assert 0 < session.remaining <= 30


def test_close_removes_it_and_records_why(table):
    _open(table)
    closed = table.close("s-1", "testing")
    assert closed is not None
    assert closed.closed_reason == "testing"
    assert len(table) == 0


def test_closing_an_unknown_session_is_harmless(table):
    assert table.close("does-not-exist", "testing") is None


def test_revoke_sid_closes_every_session_for_that_identity(table):
    """What the Controller calls when a device's trust score collapses.

    Sessions belonging to other identities must survive.
    """
    _open(table, session_id="s-1", sid="sid-alice", port=22)
    _open(table, session_id="s-2", sid="sid-alice", port=443)
    _open(table, session_id="s-3", sid="sid-bob", port=22)

    closed = table.revoke_sid("sid-alice")

    assert len(closed) == 2
    assert {c.session_id for c in closed} == {"s-1", "s-2"}
    assert all(c.closed_reason == "revoked by Controller" for c in closed)
    assert [s.session_id for s in table.active()] == ["s-3"]


def test_revoke_sid_with_no_matching_sessions(table):
    _open(table, sid="sid-alice")
    assert table.revoke_sid("sid-nobody") == []
    assert len(table) == 1


def test_a_limited_session_keeps_its_host_list(table):
    session = _open(table, acl="LIMITED", hosts=("10.0.0.5", "10.0.0.6"))
    assert session.acl == "LIMITED"
    assert session.hosts == ("10.0.0.5", "10.0.0.6")


def test_expired_is_true_once_the_lease_runs_out(table):
    session = _open(table, ttl=-1)         # already past its deadline
    assert session.expired
    assert session.remaining == 0.0


def test_the_reaper_closes_expired_leases(table):
    table.start_reaper(interval=0.05)
    _open(table, ttl=0.1)
    assert len(table) == 1

    deadline = time.time() + 2.0
    while len(table) and time.time() < deadline:
        time.sleep(0.05)

    assert len(table) == 0, "the reaper should have closed the expired lease"


def test_the_reaper_leaves_live_leases_alone(table):
    table.start_reaper(interval=0.05)
    _open(table, ttl=30)
    time.sleep(0.2)
    assert len(table) == 1


def test_stop_closes_everything(table):
    _open(table, session_id="s-1", sid="a")
    _open(table, session_id="s-2", sid="b")
    table.stop()
    assert len(table) == 0


def test_active_is_ordered_by_when_it_opened(table):
    _open(table, session_id="s-1", sid="a")
    time.sleep(0.01)
    _open(table, session_id="s-2", sid="b")
    assert [s.session_id for s in table.active()] == ["s-1", "s-2"]


# --------------------------------------------------------------------------- #
# A LIMITED grant has to be usable                                            #
# --------------------------------------------------------------------------- #

def test_a_limited_lease_opens_a_hole_the_client_can_actually_use(monkeypatch):
    """Regression: LIMITED sessions were admitted and then silently blocked.

    open() used to insert one rule per permitted host with that host as
    `ip daddr`. Those rules sit on the INPUT hook, which only sees packets
    addressed to the Gateway -- and the Gateway is a terminating proxy, so a
    client addresses its own port 443, never the resource. The daddr could
    not match, so the connection fell through to the default-deny underneath.

    Observed end to end before the fix: the knock returned SPA_OK, the
    session opened with acl=LIMITED hosts=resource-node, and the client's
    TLS handshake to the proxy then timed out. Only FULL grants worked,
    because an empty `hosts` wrote no daddr.

    The destination restriction belongs to the inner leg, and the proxy
    enforces it there (router.check_acl -> 403).
    """
    from firewall import rules, sessions

    inserted = []
    monkeypatch.setattr(rules, "allow",
                        lambda *a, **k: inserted.append((a, k)) or True)
    monkeypatch.setattr(rules, "revoke", lambda *a, **k: None)

    table = sessions.SessionTable()
    table.open(session_id="s-limited", sid="sid-limited", client_ip="10.0.0.21",
               access_port=443, protocol="tcp", ttl_seconds=300,
               acl="LIMITED", hosts=("resource-node",), posture_signals={})

    assert len(inserted) == 1, (
        f"expected exactly one inbound rule, got {len(inserted)}")
    args, kwargs = inserted[0]
    assert kwargs.get("dst_ip") is None, (
        "the inbound pinhole must not be pinned to a destination; the input "
        "hook never sees the resource as the destination")
    assert "resource-node" not in args, (
        "the permitted host leaked into the inbound rule")


def test_closing_removes_the_same_rule_that_was_opened(monkeypatch):
    """The revoke has to mirror the allow, or the hole outlives the session.

    Revoking per-host while opening once meant nftables was asked to delete a
    rule that was never inserted; it logged "revoke skipped - rule not found"
    and left the real pinhole open.
    """
    from firewall import rules, sessions

    opened, closed = [], []
    monkeypatch.setattr(rules, "allow",
                        lambda *a, **k: opened.append((a, k)) or True)
    monkeypatch.setattr(rules, "revoke", lambda *a, **k: closed.append((a, k)))

    table = sessions.SessionTable()
    table.open(session_id="s-mirror", sid="sid-mirror", client_ip="10.0.0.21",
               access_port=443, protocol="tcp", ttl_seconds=300,
               acl="LIMITED", hosts=("resource-node",), posture_signals={})
    table.close("s-mirror", "done")

    assert len(opened) == len(closed) == 1
    assert opened[0] == closed[0], (
        f"opened {opened[0]} but revoked {closed[0]}")
