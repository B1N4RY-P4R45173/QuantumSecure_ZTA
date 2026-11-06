"""Device-posture normalisation: what the IDP will sign into a knock ticket.

The Gateway's trust scorer weighs six boolean signals, and the knock carries
only one byte for them (shared/utils/knock_ticket.py). This module is the
single place that decides what those six bits say.

Why the IDP decides and not the client
--------------------------------------
The byte sits inside the ticket, under the IDP's ES256 signature, and the
Gateway verifies the signature before reading it. So the client cannot set
its own trust: it can only submit evidence, and the weight of that evidence
depends on who can be held to it. The six signals split in two:

  IDP-attested - the client has no say. Read here from what the IDP itself
  recorded during enrolment and stores in its own database:

    device_managed      this (user, device) has a credential the IDP proved
                        was born in hardware and cannot leave it. The IDP ran
                        that attestation itself at registration time
                        (fido2_idp/attestation_tpm.py) and wrote the verdict
                        to the credential row.
    known_device        this device_id already has a stored credential, i.e.
                        the IDP has seen it enrol before.
    location_expected   origin matches the user's baseline. See below.

  Client-reported - self-asserted telemetry out of PostureReport. A machine
  that is compromised, or merely lying, can claim all three, so they are
  worth less and the scorer weights them accordingly (5 + 15 + 5 points
  against the 35 the attested bits carry):

    os_patched          PostureReport.os_patch_days within MAX_PATCH_AGE_DAYS
    disk_encrypted      PostureReport.disk_encrypted
    antivirus_running   PostureReport.antivirus_active

Keeping the split visible is the point. Signing a client's self-report would
make the signature a rubber stamp; dropping the self-report would throw away
the only posture evidence that exists today. Both are signed, and which is
which stays legible in the log line this module prints.

Unknown is untrusted
--------------------
Every bit defaults to false. A missing report, a malformed report, a device
with no attested credential, a signal that cannot be computed - all pack as
false, never as true and never as an error. That is the same rule the trust
scorer applies to an absent signal, and it is the only safe direction for a
default: the cost of a false `false` is a lower score, the cost of a false
`true` is admitting a machine on evidence nobody ever had.

location_expected is false, honestly
------------------------------------
It cannot be computed today. geo/resolver.py is a Milestone-4 stub that
returns None for every address, so the IDP has no coordinates for this
request and no stored baseline to compare them against. Unknown is untrusted,
so the bit packs as false and this device simply forgoes those 10 points.
It becomes computable when geo/resolver.py returns real "lat,lon" AND a
per-user location baseline exists to compare against - the same two pieces
policy/baseline.py is waiting on for its impossible-travel check.
"""

from __future__ import annotations

import time

from pydantic import ValidationError

from store import credentials as cred_store
from shared.config.settings import settings
from shared.schemas.posture import PostureReport
from shared.utils import knock_ticket as ticket_format
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Posture")

# Patch-age policy. Env-overridable as IDP_POSTURE_MAX_PATCH_AGE_DAYS; see
# shared/config/settings.py for why 30.
MAX_PATCH_AGE_DAYS = settings.idp_posture_max_patch_age_days

# The three signals that come from the client's own report, as opposed to the
# three the IDP reads from its own records. Only these are remembered per
# session; see remember() for why.
CLIENT_REPORTED_BITS = ("os_patched", "disk_encrypted", "antivirus_running")

# sid -> (client-reported bits, expiry). The client sends its report once, at
# FIDO2 time; /token/knock-ticket reissues a ticket per knock and must not
# have to ask for it again. In-process and deliberately not in the database:
# losing it costs a session its three weakest bits until the next full login,
# which is a score penalty, not a failure. Entries expire with the refresh
# token whose session they describe, so the map cannot grow without bound.
_SESSION_BITS: dict[str, tuple[dict[str, bool], float]] = {}


def parse_report(raw: object) -> PostureReport | None:
    """A posture report off the wire, or None when there is no usable one.

    Never raises. A client that sends nothing, sends junk, or sends a report
    missing required fields loses its three client-reported bits; it does not
    lose its login. Posture is evidence for a trust score, and a device with
    no evidence should score low, not be refused at the door - that decision
    belongs to the Gateway's threshold, not to a parse error here.
    """
    if raw is None:
        return None
    if isinstance(raw, PostureReport):
        return raw
    if not isinstance(raw, dict):
        status(log, "Posture report ignored", reason="not an object",
               received_type=type(raw).__name__)
        return None
    try:
        return PostureReport.model_validate(raw)
    except ValidationError as exc:
        # Logged, not raised: see the docstring.
        status(log, "Posture report ignored", reason="failed validation",
               error_count=exc.error_count())
        return None


def evaluate(report: PostureReport | None, *, user_id: str, device_id: str) -> dict[str, bool]:
    """The six signals for this device, ready for ticket_format.pack_posture.

    `report` is the client's self-assertion (None when it sent none);
    `user_id` and `device_id` are the verified identities the IDP read out of
    the login token, and are what the IDP-attested bits are looked up by.
    """
    return _decide(_client_bits(report), user_id=user_id, device_id=device_id,
                   evidence="client report" if report is not None else "no client report")


def remember(sid: str, signals: dict[str, bool]) -> None:
    """Keep this session's client-reported bits for later reissues.

    Only those three. The IDP-attested bits are re-read from the credential
    store on every reissue instead of being cached, so that a device which
    loses its attested credential - revoked, re-enrolled without attestation -
    stops claiming device_managed on its very next knock rather than keeping
    it for the remaining hours of the session.
    """
    now = time.time()
    for expired in [s for s, (_, exp) in _SESSION_BITS.items() if exp <= now]:
        del _SESSION_BITS[expired]
    _SESSION_BITS[sid] = (
        {name: signals.get(name) is True for name in CLIENT_REPORTED_BITS},
        now + settings.idp_refresh_ttl_seconds,
    )


def for_session(sid: str, *, user_id: str, device_id: str) -> dict[str, bool]:
    """The six signals for a ticket reissued on a refresh token.

    The attested bits are read fresh; the client-reported bits come from what
    this session submitted at FIDO2 time. A session with nothing on record -
    opened before posture existed, or outliving an IDP restart - gets false
    for all three.
    """
    entry = _SESSION_BITS.get(sid)
    if entry is not None and entry[1] <= time.time():
        del _SESSION_BITS[sid]
        entry = None
    if entry is None:
        status(log, "No posture on record for this session",
               sid=sid, consequence="client-reported bits pack as false")
        return _decide(_client_bits(None), user_id=user_id, device_id=device_id,
                       evidence="no posture on record for this session")
    return _decide(entry[0], user_id=user_id, device_id=device_id,
                   evidence="posture recorded at FIDO2 time")


# --------------------------------------------------------------------------- #
# internals                                                                   #
# --------------------------------------------------------------------------- #

def _client_bits(report: PostureReport | None) -> dict[str, bool]:
    """The three self-asserted signals, or all false when there is no report."""
    if report is None:
        return {name: False for name in CLIENT_REPORTED_BITS}
    return {
        "os_patched": report.os_patch_days <= MAX_PATCH_AGE_DAYS,
        # `is True` rather than truthiness: pydantic has already coerced these
        # to bool, but the same rule as pack_posture reads better than relying
        # on it, and a schema change cannot quietly make a string count as yes.
        "disk_encrypted": report.disk_encrypted is True,
        "antivirus_running": report.antivirus_active is True,
    }


def _decide(client_bits: dict[str, bool], *, user_id: str, device_id: str,
            evidence: str) -> dict[str, bool]:
    """Join the IDP's own records to the client's bits and log the result."""
    enrolled = [c for c in cred_store.for_user(user_id) if c.device_id == device_id]

    signals = {
        # Proven in hardware by an attestation the IDP verified itself. Note
        # this reads `attested_hardware`, not the trust path: a credential
        # admitted on an administrator exception is stored with
        # attested_hardware=False precisely because the exception permits the
        # enrolment without inventing the proof, so it does not earn this bit.
        "device_managed": any(c.attested_hardware for c in enrolled),
        # Seen enrolling before, which is weaker than attested but still the
        # IDP's own observation rather than the client's claim.
        "known_device": bool(enrolled),
        # Not computable today - see the module docstring. Packed false on
        # purpose; do not default this to true.
        "location_expected": False,
        **client_bits,
    }

    # INFO, with every bit named, so an operator reading the IDP log can see
    # exactly why a device scored as it did without re-deriving the byte.
    status(log, "Device posture decided", user_id=user_id, device_id=device_id,
           evidence=evidence, credentials_on_this_device=len(enrolled),
           posture_byte=f"0x{ticket_format.pack_posture(signals):02x}",
           max_patch_age_days=MAX_PATCH_AGE_DAYS,
           **{name: signals[name] for name in ticket_format.POSTURE_BITS})
    return signals
