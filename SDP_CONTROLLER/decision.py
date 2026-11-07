"""The access decision, with nothing underneath it but policy.

This module answers one question — may this verified knock have a grant, and
how wide — and it answers it the same way whether the caller is the Gateway's
own in-process adapter or a Controller service on another host. That is the
whole reason it exists: two copies of this judgement would drift, and the
first symptom of the drift would be a remote deployment quietly allowing
something the local one refused.

It knows nothing about transport, sockets, firewalls or session tables. It
takes facts and returns a verdict. Enforcement, revocation and the wire are
somebody else's problem:

    SDP_GATEWAY/controller/policy_controller.py   in-process adapter
    SDP_CONTROLLER/service/                       the same engine over mTLS

WHAT IS ASSUMED, AND WHY
A knock carries an IDP session id, not a user. The ticket proves the IDP
authenticated somebody and attested their device; it does not say who. So
the request handed to the policy engine fills the gaps it must, and every
assumption leans the unsafe way for the client:

  role        `employee`, never `admin` — guessing the privileged role is the
              one mistake that cannot be walked back.
  country     `unknown`. No GeoIP feed is wired in, so deny-blocked-country
              can only fire if an operator pins a country. A guessed country
              is worse than none.
  action      `write`. An open port permits writes, so write is the honest
              worst case.
  posture     only what the IDP signed into the ticket. Nothing here invents
              a signal, not even `known_device`, which is always true in
              practice — see _attested_signals.

RESOLVING THE SID TO A REAL USER would replace three of those assumptions
with facts, and is the single highest-value improvement available to this
module. It needs a lookup the Gateway deliberately does not have.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from SDP_CONTROLLER import engine, trust_scorer
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Decision")

_HERE = Path(__file__).resolve().parent

ACL_FULL = "FULL"
ACL_LIMITED = "LIMITED"
# Same vocabulary SDP_GATEWAY/firewall/segmentation.py uses. Only ever
# returned alongside a refusal reason, so the reply is a denial and no grant
# is attempted.
ACL_DENY = "DENY"

DEFAULT_TTL_SECONDS = int(os.environ.get("GATEWAY_POLICY_TTL_SECONDS", "30"))

POLICIES_PATH = os.environ.get("GATEWAY_POLICY_PATH", str(_HERE / "policies.yaml"))
TELEMETRY_PATH = os.environ.get(
    "GATEWAY_TELEMETRY_PATH", str(_HERE / "telemetry_snapshot.json"))

# shared settings express the trust thresholds as fractions; the scorer works
# on 0..100. Reusing them keeps the ACL width and the rest of the project on
# one pair of numbers instead of two.
FULL_MIN_SCORE = int(round(settings.trust_threshold_full * 100))        # 70
LIMITED_MIN_SCORE = int(round(settings.trust_threshold_limited * 100))  # 40

DEFAULT_ROLE = os.environ.get("GATEWAY_POLICY_DEFAULT_ROLE", "employee")
DEFAULT_DEPARTMENT = os.environ.get("GATEWAY_POLICY_DEFAULT_DEPARTMENT", "unknown")
DEFAULT_COUNTRY = os.environ.get("GATEWAY_POLICY_DEFAULT_COUNTRY", "unknown")
DEFAULT_ACTION = os.environ.get("GATEWAY_POLICY_DEFAULT_ACTION", "write")

# The destinations an acl=LIMITED grant may reach. segmentation.py refuses a
# LIMITED grant that names none, so this must be set for the narrow band to
# work at all. iptables resolves a hostname when the rule is inserted; the
# nftables backend does not, so name IP addresses when running under nft.
LIMITED_HOSTS = tuple(
    h.strip() for h in os.environ.get("GATEWAY_POLICY_LIMITED_HOSTS", "resource-node").split(",")
    if h.strip())

UNKNOWN_PORT_CLASS = os.environ.get("GATEWAY_POLICY_UNKNOWN_PORT_CLASS", "confidential")


def _parse_port_classes(spec: str) -> dict[int, str]:
    """Parse "80=public,443=internal,22=admin" into {port: classification}.

    A malformed entry is skipped rather than fatal: one typo in an operator's
    environment must not take the Controller down, and the unmapped port then
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


@dataclass(frozen=True)
class Decision:
    """One verdict. `approved` is the only field a caller must honour."""

    approved: bool
    reason: str = ""                                # why denied; "" if approved
    score: int = 0                                  # 0..100
    acl: str = ACL_DENY                             # FULL | LIMITED | DENY
    allowed_hosts: tuple[str, ...] = ()             # () means any destination
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    breakdown: dict = field(default_factory=dict)   # posture/suricata/ml + notes
    session_id: str | None = None                   # minted only on approval


class PolicyEngine:
    """Scores a device and evaluates policy. Reusable, thread-safe, no I/O
    beyond reading its two input files."""

    def __init__(self, *, policies_path: str | None = None,
                 telemetry_path: str | None = None,
                 ttl_seconds: int | None = None) -> None:
        self._policies_path = policies_path or POLICIES_PATH
        self._telemetry_path = telemetry_path or TELEMETRY_PATH
        self._ttl_seconds = DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        self._lock = threading.Lock()
        self._policies: list[engine.Policy] = []
        self._policies_mtime: float | None = None
        self._telemetry: dict[str, dict] = {}
        self._telemetry_mtime: float | None = None

        # Fail fast, and say why. Something that cannot read its policy file
        # must not come up appearing to enforce one.
        try:
            self._load_policies()
        except Exception as exc:
            raise RuntimeError(
                f"cannot load policies from {self._policies_path!r} - aborting startup: {exc}"
            ) from exc
        status(log, "Policy engine ready", policies=self._policies_path,
               rules=len(self._policies), telemetry=self._telemetry_path,
               full_at=FULL_MIN_SCORE, limited_at=LIMITED_MIN_SCORE,
               assumed_role=DEFAULT_ROLE, ttl=f"{self._ttl_seconds}s")

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @property
    def policies_path(self) -> str:
        return self._policies_path

    @property
    def telemetry_path(self) -> str:
        return self._telemetry_path

    # -- the decision ------------------------------------------------------

    def decide(self, *, client_ip: str, access_port: int, protocol: str,
               sid: str, posture: dict[str, bool] | None = None,
               received_at: float | None = None) -> Decision:
        """Judge one verified knock.

        Never raises for a policy outcome: a refusal is a Decision with
        approved=False and a reason. It raises only if the inputs themselves
        cannot be read, which the caller must treat as a denial.
        """
        try:
            policies, telemetry = self._current_inputs()
        except Exception as exc:
            # An unreadable policy file leaves no basis on which to allow
            # anything. It denies rather than falling back to a previously
            # loaded set that may be exactly what the operator was replacing.
            status(log, "DENIED - policy load failed", client_ip=client_ip, sid=sid,
                   path=self._policies_path, error=str(exc))
            return Decision(approved=False, reason=f"policy load failed: {exc}")

        request = trust_scorer.enrich_request(
            self._build_request(client_ip=client_ip, access_port=access_port,
                                protocol=protocol, sid=sid, posture=posture,
                                received_at=received_at),
            telemetry=telemetry)
        verdict = engine.evaluate(policies, request)

        device = request["device"]
        score = int(device["trust_score"])
        breakdown = device["trust_breakdown"]

        status(log, "Trust score computed", client_ip=client_ip, sid=sid,
               score=f"{score}/100",
               posture=f"{breakdown['posture']}/{trust_scorer.POSTURE_MAX}",
               suricata=f"{breakdown['suricata']}/{trust_scorer.SURICATA_MAX}",
               ml=f"{breakdown['ml']}/{trust_scorer.ML_MAX}",
               resource=request["resource"]["classification"],
               role=request["user"]["role"], action=request["context"]["action"],
               # Which signals the IDP actually attested, so a score can be
               # read back to its evidence without turning on debug logging.
               attested=",".join(n for n, held in device["signals"].items() if held) or "none")
        for note in breakdown["notes"]:
            status(log, f"  trust | {note}")

        if verdict.verdict != "ALLOW":
            reason = f"trust={score}; " + "; ".join(verdict.reasons)
            status(log, "DENIED by policy", client_ip=client_ip, sid=sid,
                   score=score, reason=reason)
            return Decision(approved=False, reason=reason, score=score,
                            breakdown=breakdown)

        acl, hosts, refusal = self._acl_for(score, verdict.obligations)
        if refusal is not None:
            reason = f"trust={score}; {refusal}"
            status(log, "DENIED - allow could not be translated into a grant",
                   client_ip=client_ip, sid=sid, score=score, reason=reason)
            return Decision(approved=False, reason=reason, score=score,
                            acl=ACL_DENY, breakdown=breakdown)

        session_id = str(uuid.uuid4())
        status(log, "APPROVED by policy", session=session_id[:8], client_ip=client_ip,
               sid=sid, score=score, acl=acl, hosts=",".join(hosts) or "any",
               obligations=",".join(verdict.obligations) or "none",
               ttl=f"{self._ttl_seconds}s",
               matched=",".join(m.policy.id for m in verdict.matched if m.matched))
        return Decision(approved=True, score=score, acl=acl, allowed_hosts=hosts,
                        ttl_seconds=self._ttl_seconds, breakdown=breakdown,
                        session_id=session_id)

    # -- continuous re-evaluation -----------------------------------------

    def review(self, sessions: list[dict]) -> list[dict]:
        """Re-score live sessions and name the ones that should now be revoked.

        This is what separates Zero Trust from authorise-once. A grant made at
        admission reflects the evidence available in that instant; the evidence
        then changes — a detector rewrites the telemetry snapshot, an operator
        edits policies.yaml.

        Returns [{"session_id", "sid", "reason"}] for each session to close.
        An empty list means every session still passes.

        It re-reads policy and telemetry but NOT posture: posture arrives
        attested inside a knock ticket and there is no honest way to re-derive
        it between knocks, so each session carries its admission-time value.
        A device whose posture decays is caught at its next knock, not
        mid-session. That gap is real and worth stating rather than hiding.
        """
        if not sessions:
            return []

        try:
            self._current_inputs()
        except Exception as exc:
            # Same rule as decide(): an unreadable policy file is not a licence
            # to keep existing sessions open on a policy nobody can read.
            # Revoking everything is the safe direction, and loud.
            status(log, "REVIEW - policy load failed, revoking every live session",
                   sessions=len(sessions), error=str(exc))
            return [{"session_id": s.get("session_id"), "sid": s.get("sid"),
                     "reason": f"policy unreadable: {exc}"} for s in sessions]

        revoke: list[dict] = []
        for session in sessions:
            keep, score, reason = self._recheck(session)
            if keep:
                continue
            status(log, "REVOKE - session no longer passes policy",
                   session=str(session.get("session_id"))[:8], sid=session.get("sid"),
                   client_ip=session.get("client_ip"), score=score, reason=reason)
            revoke.append({"session_id": session.get("session_id"),
                           "sid": session.get("sid"), "reason": reason})

        if revoke:
            status(log, "Review complete", checked=len(sessions), revoked=len(revoke))
        return revoke

    def _recheck(self, session: dict) -> tuple[bool, int, str]:
        """Score one live session against current evidence."""
        try:
            decision = self.decide(
                client_ip=session["client_ip"],
                access_port=int(session["access_port"]),
                protocol=session.get("protocol", "tcp"),
                sid=session.get("sid", "unknown"),
                posture=session.get("posture") or {},
            )
        except Exception as exc:
            # A session that cannot be scored cannot be justified.
            return False, 0, f"re-scoring failed: {type(exc).__name__}: {exc}"

        if not decision.approved:
            return False, decision.score, decision.reason
        if decision.acl == ACL_DENY:
            return False, decision.score, "acl collapsed to DENY"
        return True, decision.score, ""

    # -- decision -> grant -------------------------------------------------

    def _acl_for(self, score: int,
                 obligations: list[str]) -> tuple[str, tuple[str, ...], str | None]:
        """Translate an ALLOW into an ACL width, or refuse with a reason.

        WHY THE OBLIGATIONS MAP THIS WAY. `require_mfa` and `require_stepup`
        ask for an interactive challenge. This seam cannot issue one: it is
        answering a single UDP knock, the client is not in a dialogue, and
        what the Gateway hands out is an L3/L4 hole. An obligation that cannot
        be satisfied must not be silently dropped — that would quietly delete
        a control the operator wrote — so each is mapped to the nearest thing
        enforcement can actually express:

          require_mfa     -> narrow FULL to LIMITED. The knock already proves
                             a verified FIDO2 login, so policies.yaml is
                             asking for a step-up on top of that, not a
                             missing first factor. The honest answer to an
                             unmet step-up is a smaller grant, not a denial.
                             It only ever narrows; it can never widen.
          require_stepup  -> deny. This fires only on a write or delete
                             against an admin-classified resource. No ACL
                             width makes an unauthenticated privileged write
                             safe, so there is nothing to narrow to.

        The trust bands are not a second policy layer; they are the same
        translation applied to the score.
        """
        if "require_stepup" in obligations:
            return ACL_DENY, (), "obligation require_stepup cannot be satisfied at the SPA seam"

        if score >= FULL_MIN_SCORE:
            acl, hosts = ACL_FULL, ()
        elif score >= LIMITED_MIN_SCORE:
            acl, hosts = ACL_LIMITED, LIMITED_HOSTS
        else:
            return ACL_DENY, (), f"trust below the LIMITED floor of {LIMITED_MIN_SCORE}"

        if "require_mfa" in obligations and acl == ACL_FULL:
            acl, hosts = ACL_LIMITED, LIMITED_HOSTS

        if acl == ACL_LIMITED and not hosts:
            # segmentation.py would refuse this grant and the listener would
            # drop the knock with nothing to explain it. Say so here instead.
            return ACL_DENY, (), "acl=LIMITED but GATEWAY_POLICY_LIMITED_HOSTS names no destination"

        return acl, hosts, None

    # -- request construction ---------------------------------------------

    def _build_request(self, *, client_ip: str, access_port: int, protocol: str,
                       sid: str, posture: dict[str, bool] | None,
                       received_at: float | None) -> dict:
        """Shape a verified knock as the access request engine.py expects.

        Same four blocks as SDP_CONTROLLER/scenarios.yaml — user, device,
        resource, context — because that is the only context policies.yaml
        expressions can name. Every assumed value is justified in the module
        docstring; none is invented to make a request pass.
        """
        signals = self._attested_signals(posture)

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
                # signals, named the way policies.yaml expressions reach them.
                # Read off the attested byte rather than fixed here, so a
                # policy author cannot be shown device.managed == False next
                # to a posture score that already credited it.
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
                "hour": time.localtime(received_at or time.time()).tm_hour,
                "country": DEFAULT_COUNTRY,
                "ip": client_ip,
                "action": DEFAULT_ACTION,
            },
        }

    @staticmethod
    def _attested_signals(posture: dict | None) -> dict[str, bool]:
        """The posture the IDP signed into the knock ticket, as the scorer's
        signal dict.

        Three rules keep a missing or odd value from buying trust:

        1. The starting point is the scorer's own weight table, all False, so
           a signal added to trust_scorer defaults to untrusted here without
           this file being touched.
        2. Only a value of exactly True credits a signal. Absent, None and
           anything truthy-but-not-True read as untrusted, matching
           knock_ticket.pack_posture() at the other end of the wire and
           trust_scorer._posture_score() downstream. A client or IDP older
           than ticket version 2 therefore yields all-False and degrades to a
           denial instead of raising.
        3. Names the scorer does not weigh are dropped rather than passed
           through. That matters for more than tidiness: trust_scorer reads
           `no_suricata_alerts` and `ml_anomaly_score_ok` out of this same
           dict as a standalone substitute for telemetry and would award full
           IDS and ML credit for them. Filtering here means no posture payload
           can reach into the detection half of the score, so a device the
           pipeline has not seen keeps its conservative half credit.
        """
        signals = {name: False for name in trust_scorer.POSTURE_WEIGHTS}
        if isinstance(posture, dict):
            for name in signals:
                signals[name] = posture.get(name) is True
        return signals

    # -- inputs ------------------------------------------------------------

    def _current_inputs(self) -> tuple[list[engine.Policy], dict[str, dict]]:
        """Policies and telemetry as they are on disk right now.

        Both reload when their mtime moves, so editing policies.yaml or
        re-running the detection pipeline changes the next decision without a
        restart. The lock guards a future threaded caller from reading a
        half-swapped policy list — which the Controller service, being
        threaded, genuinely is.
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
