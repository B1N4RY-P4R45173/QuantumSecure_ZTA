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
    The knock ticket carries an IDP session id (sid), a ticket id and a
    WireGuard public key. There is no username, no role and no MDM posture in
    it, and this seam is in-process: it holds no IDP link, so the sid cannot
    be resolved to a person here. Every field of the access request is
    therefore either proven or assumed, and the assumptions are listed so a
    reviewer can see what the decision actually rests on:

    proven    `user.authenticated` and `user.mfa_verified`. The ticket is
              ES256-signed by the IDP, fresh, single-use, and was verified
              against the IDP's JWKS before this call. The IDP issues one
              only after a completed FIDO2 ceremony, i.e. a hardware-bound
              second factor was verified seconds ago. Reporting these as
              False would be asserting something untrue, would deny for the
              wrong reason (deny-admin-without-mfa), and would make every
              step-up rule in policies.yaml unreachable.
    proven    `known_device`. A ticket is only issued against a credential
              the IDP has enrolled, and it carries that device's WireGuard
              public key. This is the ONLY posture signal credited here.
    assumed   `user.role`. GATEWAY_POLICY_DEFAULT_ROLE, "employee". `admin`
              is never assumed, so allow-admin cannot fire on a knock alone,
              and no privilege is invented from an unresolved sid.
    assumed   `resource.classification`, from the port the knock asks for
              (GATEWAY_POLICY_PORT_CLASSES). An unmapped port is treated as
              the stricter GATEWAY_POLICY_UNKNOWN_PORT_CLASS.
    assumed   `context.action` = "write". The grant is an L3/L4 hole, and an
              open TCP port permits writes, so the worst case is the only
              honest one. The HTTP method is not visible until the proxy.
    unknown   MDM posture (managed, patched, encrypted, antivirus, expected
              location) and geography. Left False / "unknown" rather than
              guessed. The scorer's own convention is that unknown is
              untrusted, and nothing here overrides it.

WHY THAT FAILS CLOSED, ON PURPOSE
    With no MDM feed and no telemetry entry for the source IP, posture scores
    10/60 (known_device alone) and the scorer awards half credit for absent
    Suricata and ML evidence: 10 + 12 + 7 = 29/100. That is below
    deny-untrusted-device's floor of 40, so the knock is denied. This is the
    intended answer, not a bug: a device the detection pipeline has never
    looked at has earned nothing. The same knock from an IP the pipeline
    cleared scores 10 + 25 + 15 = 50 and is granted the narrow ACL. The fix
    for a denial is to wire real posture and run the pipeline, never to
    loosen the defaults here.
    One consequence worth stating plainly: until an MDM feed supplies posture
    signals, 50/100 is the ceiling, so acl=FULL is unreachable and every
    grant is LIMITED. FULL requires posture evidence, by design.

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

# The posture signals an operator asserts for this deployment, for the case
# where MDM exists but is not yet feeding the Gateway. Empty by default: the
# only signal credited without evidence is the one the ticket itself proves.
ASSUMED_SIGNALS = tuple(
    s.strip() for s in os.environ.get("GATEWAY_POLICY_ASSUMED_SIGNALS", "").split(",")
    if s.strip())

# Proven by the knock ticket: the IDP enrolled this device and the ticket
# carries its WireGuard key.
PROVEN_SIGNALS = ("known_device",)

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
               role=request["user"]["role"], action=request["context"]["action"])
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

        # Start from the scorer's own weight table so a new posture signal
        # there defaults to untrusted here without this file being touched.
        signals: dict[str, bool] = {name: False for name in trust_scorer.POSTURE_WEIGHTS}
        for name in PROVEN_SIGNALS + ASSUMED_SIGNALS:
            if name in signals:
                signals[name] = True
        # `no_suricata_alerts` / `ml_anomaly_score_ok` are deliberately absent.
        # trust_scorer reads them as a standalone substitute for telemetry and
        # would award full IDS/ML credit; leaving them out keeps the scorer's
        # conservative half-credit for a device the pipeline has not seen.

        return {
            "user": {
                "id": f"sid:{sid}",
                "role": DEFAULT_ROLE,
                "department": DEFAULT_DEPARTMENT,
                "authenticated": True,
                "mfa_verified": True,
            },
            "device": {
                "os": "unknown",
                "managed": False,
                "known": True,
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
