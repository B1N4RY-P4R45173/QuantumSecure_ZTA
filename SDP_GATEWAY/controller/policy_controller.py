"""The Gateway's real access decision: the project's own trust scorer and
policy engine, in process, behind the same one-method seam as the stand-in.

WHY THIS EXISTS
    AllowAllController approves every verified knock. That exercises the
    Gateway's segmentation path but applies no policy whatsoever, which is
    exactly the thing a zero-trust gateway must not do. The project already
    knows how to decide: SDP_CONTROLLER/trust_scorer.py fuses device posture,
    Suricata alerts and the ML anomaly classifier into a 0..100 score, and
    SDP_CONTROLLER/engine.py evaluates SDP_CONTROLLER/policies.yaml over the
    enriched request with zero-trust semantics (any matching deny wins; at
    least one allow must match or the request is implicitly denied). This
    class is the adapter between a verified SPA knock and those two modules.

WHAT A KNOCK PROVES, AND WHAT IT DOES NOT
    The knock ticket carries an IDP session id (sid), a ticket id, a
    WireGuard public key and one byte of device posture. There is no username
    and no role in it, and this seam is in-process: it holds no IDP link, so
    the sid cannot be resolved to a person here. Every field of the access
    request is therefore proven, attested or assumed, and the assumptions are
    listed so a reviewer can see what the decision actually rests on:

    proven    `user.authenticated` and `user.mfa_verified`. The ticket is
              ES256-signed by the IDP, fresh, single-use, and was verified
              against the IDP's JWKS before this call. The IDP issues one
              only after a completed FIDO2 ceremony, i.e. a hardware-bound
              second factor was verified seconds ago. Reporting these as
              False would be asserting something untrue, would deny for the
              wrong reason (deny-admin-without-mfa), and would make every
              step-up rule in policies.yaml unreachable.
    attested  the six posture signals, from the ticket's posture byte
              (shared/utils/knock_ticket.py). The IDP sets them and its
              signature covers them; spa/listener.py checked that signature
              before this call and passes the unpacked dict in
              identity["posture"]. Three of the six are the IDP's own
              knowledge and the client cannot influence them at all:
              device_managed (the IDP ran the hardware attestation itself),
              known_device, location_expected. The other three are relayed
              from the client's PostureReport and are self-asserted, so they
              are weaker evidence: os_patched, disk_encrypted,
              antivirus_running. This seam trusts the byte exactly as far as
              it trusts the IDP and adds nothing of its own to it.
    assumed   `user.role`. GATEWAY_POLICY_DEFAULT_ROLE, "employee". `admin`
              is never assumed, so allow-admin cannot fire on a knock alone,
              and no privilege is invented from an unresolved sid.
    assumed   `resource.classification`, from the port the knock asks for
              (GATEWAY_POLICY_PORT_CLASSES). An unmapped port is treated as
              the stricter GATEWAY_POLICY_UNKNOWN_PORT_CLASS.
    assumed   `context.action` = "write". The grant is an L3/L4 hole, and an
              open TCP port permits writes, so the worst case is the only
              honest one. The HTTP method is not visible until the proxy.
    unknown   geography. `context.country` stays "unknown" rather than
              guessed, so deny-blocked-country only fires when an operator
              pins a country. This is a different question from the attested
              `location_expected` bit, which the IDP answers against the
              user's own origin baseline, not against a country list.

WHAT THE NUMBERS COME OUT AT
    Posture is 60 of the scorer's 100 points, and for a source IP the
    detection pipeline has never seen the scorer awards half credit for the
    absent Suricata and ML evidence (12 + 7 = 19):

      all six attested          60 + 19 = 79  ALLOW, acl=FULL
      IDP-attested three only   35 + 19 = 54  ALLOW, acl=LIMITED
      client-reported three     25 + 19 = 44  no allow rule matches, because
        only                                  allow-employee-standard needs
                                              50 -> implicit deny
      no posture at all          0 + 19 = 19  under deny-untrusted-device's
                                              floor of 40 -> denied

    The middle rows are the whole point of splitting the signals by who
    attests them. Self-asserted posture alone is 25 points and cannot reach a
    grant; the three the IDP vouches for are worth 35 and earn the narrow
    ACL; only the two sets together clear FULL. The same knock from an IP the
    pipeline has cleared gets 25 + 15 instead of 19, which is why running the
    detection pipeline moves a decision as much as posture does.

    A knock whose identity carries no `posture` block - a client or IDP older
    than ticket version 2 - scores all-false and lands on the last row. It
    degrades to a denial rather than an error, because unknown is untrusted;
    that is the scorer's own convention and nothing here overrides it.

    One number worth knowing before reading a LIMITED grant as a bug:
    location_expected is false in practice today, because
    IDENTITY_PROVIDER/geo/resolver.py is still a Milestone-4 stub and the IDP
    will not attest what it cannot compute. That costs 10 points, so a device
    reporting everything else honestly scores 69 on an unseen IP - one short
    of FULL - and 90 once the pipeline has cleared its IP.

NOTE ON STATE
    Unlike the stand-in, this keeps no session dictionary of its own.
    firewall.sessions.TABLE is the Gateway's record of what is open and the
    only thing that can revoke or reap; a second copy here would only drift
    out of step with it.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from pathlib import Path

# SDP_CONTROLLER is a sibling component tree, not part of the Gateway's own
# import root (`from controller import ...`), so the repo root has to be on
# sys.path before it can be imported. main.py already inserts it; repeating it
# here keeps this module importable on its own and under pytest instead of
# depending on whichever entrypoint got there first.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from SDP_CONTROLLER import engine, trust_scorer  # noqa: E402
from firewall.sessions import TABLE  # noqa: E402
from shared.config.settings import settings  # noqa: E402
from shared.utils.logger import get_logger, status  # noqa: E402

log = get_logger("Controller")

ACL_FULL = "FULL"
ACL_LIMITED = "LIMITED"
# Same vocabulary firewall/segmentation.py uses. Only ever returned alongside
# a refusal reason, so the reply is DENIED and no grant is attempted.
ACL_DENY = "DENY"

DEFAULT_TTL_SECONDS = int(os.environ.get("GATEWAY_POLICY_TTL_SECONDS", "30"))

POLICIES_PATH = os.environ.get(
    "GATEWAY_POLICY_PATH", str(_REPO_ROOT / "SDP_CONTROLLER" / "policies.yaml"))
TELEMETRY_PATH = os.environ.get(
    "GATEWAY_TELEMETRY_PATH", str(_REPO_ROOT / "SDP_CONTROLLER" / "telemetry_snapshot.json"))

# shared settings express the trust thresholds as fractions; the scorer works
# on 0..100. Reusing them keeps the Gateway's ACL width and the rest of the
# project on one pair of numbers instead of two.
FULL_MIN_SCORE = int(round(settings.trust_threshold_full * 100))        # 70
LIMITED_MIN_SCORE = int(round(settings.trust_threshold_limited * 100))  # 40

# What an unresolved sid is assumed to be. See the docstring: never "admin".
DEFAULT_ROLE = os.environ.get("GATEWAY_POLICY_DEFAULT_ROLE", "employee")
DEFAULT_DEPARTMENT = os.environ.get("GATEWAY_POLICY_DEFAULT_DEPARTMENT", "unknown")
# No GeoIP feed is wired in, so deny-blocked-country can only fire when an
# operator pins a country here. A guessed country would be worse than none.
DEFAULT_COUNTRY = os.environ.get("GATEWAY_POLICY_DEFAULT_COUNTRY", "unknown")
# An open port permits writes, so "write" is the honest worst case.
DEFAULT_ACTION = os.environ.get("GATEWAY_POLICY_DEFAULT_ACTION", "write")

# The destinations an acl=LIMITED grant may reach. segmentation.py refuses a
# LIMITED grant that names none, so this must be set for the narrow band to
# work at all. Default is the one resource behind the Gateway in this
# topology. iptables resolves a hostname when the rule is inserted; the
# nftables backend does not, so name IP addresses when running under nft.
LIMITED_HOSTS = tuple(
    h.strip() for h in os.environ.get("GATEWAY_POLICY_LIMITED_HOSTS", "resource-node").split(",")
    if h.strip())

# Posture comes from the ticket's signed byte and from nowhere else. There is
# deliberately no environment knob for asserting a signal locally, and no
# hard-coded credit for `known_device` even though a ticket is only ever issued
# against an enrolled credential: either would let this seam hand the scorer a
# signal the IDP did not sign, which is the exact gap the posture byte exists to
# close. The IDP already reports known_device in the byte, so taking it from
# there instead costs nothing and keeps one authority for all six.

UNKNOWN_PORT_CLASS = os.environ.get("GATEWAY_POLICY_UNKNOWN_PORT_CLASS", "confidential")


def _parse_port_classes(spec: str) -> dict[int, str]:
    """Parse "80=public,443=internal,22=admin" into {port: classification}.

    A malformed entry is skipped rather than fatal: one typo in an operator's
    environment must not take the Gateway down, and the unmapped port then
    falls through to the stricter UNKNOWN_PORT_CLASS anyway.
    """
    out: dict[int, str] = {}
    for item in spec.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        port_text, classification = item.split("=", 1)
        try:
            out[int(port_text.strip())] = classification.strip()
        except ValueError:
            status(log, "Ignoring malformed port classification", entry=item)
    return out


PORT_CLASSES = _parse_port_classes(
    os.environ.get("GATEWAY_POLICY_PORT_CLASSES", "80=public,443=internal,22=admin"))


class PolicyController:
    """Decides one verified knock with trust_scorer + the policy engine.

    Implements the same `send(msg) -> dict` contract as AllowAllController, so
    main.py swaps one for the other and the SPA listener does not change.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS, *,
                 policies_path: str = POLICIES_PATH,
                 telemetry_path: str = TELEMETRY_PATH) -> None:
        self._ttl_seconds = ttl_seconds
        self._policies_path = policies_path
        self._telemetry_path = telemetry_path
        self._lock = threading.Lock()
        self._policies: list[engine.Policy] = []
        self._policies_mtime: float | None = None
        self._telemetry: dict[str, dict] = {}
        self._telemetry_mtime: float | None = None

        # Fail fast, and say why: a Gateway that cannot read its policy file
        # must not come up appearing to enforce one. Same shape as main.py's
        # JWKS check, so startup aborts with a sentence rather than a
        # getmtime traceback.
        try:
            self._load_policies()
        except Exception as exc:
            raise RuntimeError(
                f"cannot load policies from {self._policies_path!r} - aborting startup: {exc}"
            ) from exc
        status(log, "Controller: policy engine ready",
               policies=self._policies_path, rules=len(self._policies),
               telemetry=self._telemetry_path,
               full_at=FULL_MIN_SCORE, limited_at=LIMITED_MIN_SCORE,
               assumed_role=DEFAULT_ROLE, ttl=f"{self._ttl_seconds}s")

    # -- the ControllerClient seam ----------------------------------------

    def send(self, msg: dict) -> dict:
        if msg.get("type") != "SPA_VERIFY":
            return {"type": "ERROR", "reason": f"unknown: {msg.get('type')}"}

        client_ip = msg["client_ip"]
        sid = (msg.get("identity") or {}).get("sid", "unknown")

        try:
            policies, telemetry = self._current_inputs()
        except Exception as exc:
            # An unreadable or invalid policy file leaves no basis on which to
            # allow anything, so it denies rather than falling back to a
            # previously loaded set that may be exactly what the operator was
            # trying to replace.
            status(log, "DENIED - policy load failed", client_ip=client_ip, sid=sid,
                   path=self._policies_path, error=str(exc))
            return {"type": "DENIED", "reason": f"policy load failed: {exc}"}

        request = trust_scorer.enrich_request(self._build_request(msg), telemetry=telemetry)
        decision = engine.evaluate(policies, request)

        device = request["device"]
        score = int(device["trust_score"])
        breakdown = device["trust_breakdown"]
        status(log, "Trust score computed", client_ip=client_ip, sid=sid, score=f"{score}/100",
               posture=f"{breakdown['posture']}/{trust_scorer.POSTURE_MAX}",
               suricata=f"{breakdown['suricata']}/{trust_scorer.SURICATA_MAX}",
               ml=f"{breakdown['ml']}/{trust_scorer.ML_MAX}",
               resource=request["resource"]["classification"],
               role=request["user"]["role"], action=request["context"]["action"],
               # Which signals the IDP actually attested, so a score can be
               # read back to its evidence without turning on debug logging.
               attested=",".join(n for n, held in request["device"]["signals"].items() if held)
                        or "none")
        for note in breakdown["notes"]:
            status(log, f"  trust | {note}")

        if decision.verdict != "ALLOW":
            reason = f"trust={score}; " + "; ".join(decision.reasons)
            status(log, "DENIED by policy", client_ip=client_ip, sid=sid,
                   score=score, reason=reason)
            return {"type": "DENIED", "reason": reason}

        acl, hosts, refusal = self._acl_for(score, decision.obligations)
        if refusal is not None:
            reason = f"trust={score}; {refusal}"
            status(log, "DENIED - allow could not be translated into a grant",
                   client_ip=client_ip, sid=sid, score=score, reason=reason)
            return {"type": "DENIED", "reason": reason}

        session_id = str(uuid.uuid4())
        status(log, "APPROVED by policy", session=session_id[:8], client_ip=client_ip, sid=sid,
               score=score, acl=acl, hosts=",".join(hosts) or "any",
               obligations=",".join(decision.obligations) or "none",
               ttl=f"{self._ttl_seconds}s",
               matched=",".join(m.policy.id for m in decision.matched if m.matched))
        return {
            "type": "APPROVED",
            "session_id": session_id,
            "access_port": msg["access_port"],
            "protocol": msg["protocol"],
            "ttl_seconds": self._ttl_seconds,
            "acl": acl,
            "allowed_hosts": list(hosts),
        }

    # -- continuous re-evaluation ------------------------------------------

    def reevaluate(self) -> list[str]:
        """Re-score every live session and revoke the ones that now fail.

        This is what separates Zero Trust from authorise-once. A grant made
        at admission reflects the evidence available in that instant; the
        evidence then changes. Suricata raises an alert against the device,
        the detection pipeline rewrites the telemetry snapshot, an operator
        edits policies.yaml. Without re-evaluation the client keeps its
        access until its lease happens to run out, which is the behaviour of
        a firewall rule, not of a policy decision.

        Re-reads policy and telemetry each pass, so an operator who tightens
        a rule or a detector that flags a device takes effect on the next
        cycle rather than at the next login.

        Returns the session ids revoked, for the caller to log.

        Deliberately re-runs the ORIGINAL decision inputs for the session,
        not a fresh posture read: posture arrives attested inside a knock
        ticket, and there is no honest way to re-derive it here between
        knocks. What is re-read is everything the Gateway can observe for
        itself - IDS alerts, ML verdicts, policy. A device whose posture
        decays is caught at its next knock, not mid-session; that gap is
        worth stating rather than papering over.
        """
        live = TABLE.active()
        if not live:
            return []

        try:
            policies, telemetry = self._current_inputs()
        except Exception as exc:
            # Same rule as send(): an unreadable policy file is not a licence
            # to keep existing sessions open on a policy nobody can read.
            # Revoking everything is the safe direction, and loud.
            status(log, "RE-EVALUATION - policy load failed, revoking all live sessions",
                   sessions=len(live), error=str(exc))
            revoked = []
            for session in live:
                revoked.extend(s.session_id for s in
                               TABLE.revoke_sid(session.sid, "policy unreadable"))
            return revoked

        revoked: list[str] = []
        for session in live:
            if session.expired:
                continue  # the reaper owns this one
            verdict, score, reason = self._rescore(session, policies, telemetry)
            if verdict:
                continue
            status(log, "REVOKING - session no longer passes policy",
                   session=session.session_id[:8], sid=session.sid,
                   client_ip=session.client_ip, score=score, reason=reason,
                   had_remaining=f"{session.remaining:.1f}s")
            revoked.extend(s.session_id for s in
                           TABLE.revoke_sid(session.sid, f"re-evaluation: {reason}"))

        if revoked:
            status(log, "Re-evaluation complete", checked=len(live), revoked=len(revoked))
        return revoked

    def _rescore(self, session, policies, telemetry) -> tuple[bool, int, str]:
        """Score one live session against current evidence.

        Rebuilds the same request shape send() used, from what the session
        itself records, so the second decision is comparable with the first.
        """
        msg = {
            "client_ip": session.client_ip,
            "access_port": session.access_port,
            "protocol": session.protocol,
            "identity": {"sid": session.sid, "posture": session.posture_signals},
        }
        try:
            request = trust_scorer.enrich_request(self._build_request(msg), telemetry=telemetry)
            decision = engine.evaluate(policies, request)
        except Exception as exc:
            # A session that cannot be scored cannot be justified.
            return False, 0, f"re-scoring failed: {exc}"

        score = int(request["device"]["trust_score"])
        if decision.verdict != "ALLOW":
            return False, score, "; ".join(decision.reasons)

        acl, _hosts, refusal = self._acl_for(score, decision.obligations)
        if refusal is not None:
            return False, score, refusal
        if acl == ACL_DENY:
            return False, score, "acl collapsed to DENY"
        return True, score, ""

    # -- decision -> grant -------------------------------------------------

    def _acl_for(self, score: int, obligations: list[str]) -> tuple[str, tuple[str, ...], str | None]:
        """Translate an ALLOW into an ACL width, or refuse with a reason.

        WHY THE OBLIGATIONS MAP THIS WAY. `require_mfa` and `require_stepup`
        ask for an interactive challenge. This seam cannot issue one: it is
        answering a single UDP knock, the client is not in a dialogue, and
        what the Gateway hands out is an L3/L4 hole that understands no
        application protocol (see firewall/segmentation.py). An obligation
        that cannot be satisfied must not be silently dropped — that would
        quietly delete a control the operator wrote — so each one is mapped to
        the nearest thing enforcement can actually express:

          require_mfa     -> narrow FULL to LIMITED. The knock already proves
                             a verified FIDO2 login, so what policies.yaml is
                             asking for is a *step-up* on top of that, not a
                             missing first factor. The honest answer to an
                             unmet step-up is a smaller grant, not a denial.
                             It only ever narrows; it can never widen.
          require_stepup  -> deny. This fires only on a write or delete
                             against an admin-classified resource. No ACL
                             width makes an unauthenticated privileged write
                             safe, so there is nothing to narrow to.

        The trust bands are not a second policy layer; they are the same
        translation applied to the score. A score at or above FULL_MIN_SCORE
        has earned every destination, one above LIMITED_MIN_SCORE has earned
        only the declared hosts, and below that there is no width left to
        hand out, so an `allow` cannot be turned into a grant at all.
        """
        if "require_stepup" in obligations:
            return ACL_DENY, (), "obligation require_stepup cannot be satisfied at the SPA seam"

        if score >= FULL_MIN_SCORE:
            acl, hosts = ACL_FULL, ()
        elif score >= LIMITED_MIN_SCORE:
            acl, hosts = ACL_LIMITED, LIMITED_HOSTS
        else:
            return (ACL_DENY, (),
                    f"trust below the LIMITED floor of {LIMITED_MIN_SCORE}")

        if "require_mfa" in obligations and acl == ACL_FULL:
            acl, hosts = ACL_LIMITED, LIMITED_HOSTS

        if acl == ACL_LIMITED and not hosts:
            # segmentation.py would refuse this grant and the listener would
            # drop the knock with nothing to explain it. Say so here instead.
            return ACL_DENY, (), "acl=LIMITED but GATEWAY_POLICY_LIMITED_HOSTS names no destination"

        return acl, hosts, None

    # -- request construction ---------------------------------------------

    def _build_request(self, msg: dict) -> dict:
        """Shape a verified knock as the access request engine.py expects.

        Same four blocks as SDP_CONTROLLER/scenarios.yaml — user, device,
        resource, context — because that is the only context policies.yaml
        expressions can name. Every assumed value is justified in the module
        docstring; none of them is invented to make a request pass.
        """
        identity = msg.get("identity") or {}
        sid = identity.get("sid", "unknown")
        access_port = msg["access_port"]
        protocol = msg.get("protocol", "tcp")
        signals = self._attested_signals(identity)

        return {
            "user": {
                "id": f"sid:{sid}",
                "role": DEFAULT_ROLE,
                "department": DEFAULT_DEPARTMENT,
                "authenticated": True,
                "mfa_verified": True,
            },
            "device": {
                # `managed` and `known` are the same two facts as the matching
                # signals, named the way policies.yaml expressions can reach
                # them. They are read off the attested byte rather than fixed
                # here, so a policy author cannot be shown device.managed ==
                # False next to a posture score that already credited it.
                "os": "unknown",
                "managed": signals.get("device_managed", False),
                "known": signals.get("known_device", False),
                "signals": signals,
            },
            "resource": {
                "name": f"{protocol}/{access_port}",
                "classification": PORT_CLASSES.get(access_port, UNKNOWN_PORT_CLASS),
                "owner": "unknown",
            },
            "context": {
                # Local time of the host, which is UTC in the container image.
                "hour": time.localtime(msg.get("received_at") or time.time()).tm_hour,
                "country": DEFAULT_COUNTRY,
                "ip": msg["client_ip"],
                "action": DEFAULT_ACTION,
            },
        }

    @staticmethod
    def _attested_signals(identity: dict) -> dict[str, bool]:
        """The posture the IDP signed into the knock ticket, as the scorer's
        signal dict.

        spa/listener.py unpacks the ticket's posture byte with
        shared.utils.knock_ticket.unpack_posture() and puts the result in
        identity["posture"], already under these names. The work left here is
        the three rules that keep a missing or odd value from buying trust:

        1. The starting point is the scorer's own weight table, all False, so
           a signal added to trust_scorer defaults to untrusted here without
           this file being touched.
        2. Only a value of exactly True credits a signal. Absent, None and
           anything truthy-but-not-True read as untrusted, matching
           knock_ticket.pack_posture() at the other end of the wire and
           trust_scorer._posture_score() downstream. An identity with no
           `posture` block at all - a client or IDP older than ticket
           version 2 - therefore yields all-False and degrades to a denial
           instead of raising.
        3. Names the scorer does not weigh are dropped rather than passed
           through. That matters for more than tidiness: trust_scorer reads
           `no_suricata_alerts` and `ml_anomaly_score_ok` out of this same
           dict as a standalone substitute for telemetry and would award full
           IDS and ML credit for them. Filtering here means no posture
           payload can reach into the detection half of the score, so a
           device the pipeline has not seen keeps its conservative half
           credit.
        """
        attested = identity.get("posture")
        signals = {name: False for name in trust_scorer.POSTURE_WEIGHTS}
        if isinstance(attested, dict):
            for name in signals:
                signals[name] = attested.get(name) is True
        return signals

    # -- inputs ------------------------------------------------------------

    def _current_inputs(self) -> tuple[list[engine.Policy], dict[str, dict]]:
        """Policies and telemetry as they are on disk right now.

        Both are reloaded when their mtime moves, so editing policies.yaml or
        re-running the detection pipeline changes the next decision without a
        Gateway restart — the same live-edit behaviour demo.py relies on. The
        SPA listener is single-threaded today; the lock is here so a future
        threaded listener cannot read a half-swapped policy list.
        """
        with self._lock:
            self._load_policies()
            self._load_telemetry()
            return list(self._policies), dict(self._telemetry)

    def _load_policies(self) -> None:
        mtime = os.path.getmtime(self._policies_path)
        if mtime == self._policies_mtime:
            return
        policies = engine.load_policies(self._policies_path)
        self._policies, self._policies_mtime = policies, mtime
        status(log, "Policies loaded", path=self._policies_path, rules=len(policies))

    def _load_telemetry(self) -> None:
        """Missing telemetry is normal, not an error: the scorer treats an
        absent entry as unknown and scores it at half credit."""
        try:
            mtime = os.path.getmtime(self._telemetry_path)
        except OSError:
            self._telemetry, self._telemetry_mtime = {}, None
            return
        if mtime == self._telemetry_mtime:
            return
        self._telemetry = trust_scorer.load_telemetry(self._telemetry_path)
        self._telemetry_mtime = mtime
        status(log, "Telemetry snapshot loaded", path=self._telemetry_path,
               devices=len(self._telemetry))
