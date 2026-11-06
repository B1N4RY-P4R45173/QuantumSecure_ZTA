"""Wire format of the knock ticket: the small, IDP-signed token that rides
inside the SPA knock in place of the full access JWT.

The access JWT is ~1 KB. An ML-KEM-768 knock already spends 1116 bytes on
the KEM ciphertext, nonce and tag, which leaves ~356 bytes of a 1472-byte
UDP payload for everything else. The ticket is 134 bytes.

Layout (big-endian, 134 bytes):

    byte  0        version            2
    bytes 1-16     sid                session id (UUID), same as the JWTs
    bytes 17-32    one-time id        UUID; the Gateway accepts it once
    bytes 33-36    expiry             unix seconds, issue time + 60 s
    bytes 37-68    WireGuard key      client's 32-byte WireGuard public key
    byte  69       posture            six device-posture bits (see below)
    bytes 70-133   IDP signature      ES256 (P-256, SHA-256), raw r||s,
                                      over bytes 0-69

Signing lives only in the IDP. This module defines the layout once, for the
IDP that builds it and the Gateway that checks it, so the two cannot drift.

Why posture rides in the ticket
-------------------------------
The Gateway's Controller scores device trust, but the knock carries only a
session id — so without this byte every device scores as unknown, lands
under the deny threshold, and nothing is ever granted.

It goes in the ticket rather than the knock payload because the ticket is
signed by the IDP and the payload is not. A client that reported its own
posture directly could simply claim to be patched. Here the IDP decides what
the bits say, and the Gateway verifies the signature before reading them, so
posture is attested rather than asserted.

One byte buys all six signals the trust scorer weighs, against roughly 220
bytes of remaining room in the datagram — the cheapest part of the design.

Version 2 is not backward compatible with version 1, deliberately. A v1
ticket has no posture byte, so accepting one would mean scoring a device as
having no posture at all, which the policy reads as untrusted. The IDP and
Gateway deploy together; a rejected v1 ticket is a clear error rather than a
silent downgrade.
"""

from __future__ import annotations

import struct
import time
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from shared.utils.crypto import ecdsa_raw_to_der

VERSION = 2
WG_KEY_LEN = 32
SIGNATURE_LEN = 64
_BODY = struct.Struct(">B16s16sI32sB")   # 70 bytes
TICKET_LEN = _BODY.size + SIGNATURE_LEN  # 134

# The six signals SDP_CONTROLLER/trust_scorer.py weighs, in bit order. The
# names are the scorer's own, so the Gateway can hand the unpacked dict
# straight to it without a translation table that could drift.
POSTURE_BITS = (
    "device_managed",      # bit 0 - enrolled with a verified hardware anchor
    "os_patched",          # bit 1 - within the patch-age threshold
    "known_device",        # bit 2 - this device_id has enrolled before
    "location_expected",   # bit 3 - origin matches the user's baseline
    "disk_encrypted",      # bit 4 - full-disk encryption on
    "antivirus_running",   # bit 5 - endpoint protection alive
)


class InvalidTicket(ValueError):
    pass


def pack_posture(signals: dict[str, bool]) -> int:
    """Six booleans -> one byte. A signal that is absent, None, or anything
    other than exactly True packs as 0: unknown is untrusted, which is the
    same rule the trust scorer applies."""
    packed = 0
    for index, name in enumerate(POSTURE_BITS):
        if signals.get(name) is True:
            packed |= 1 << index
    return packed


def unpack_posture(packed: int) -> dict[str, bool]:
    """One byte -> the signal dict the trust scorer consumes."""
    return {name: bool(packed & (1 << index))
            for index, name in enumerate(POSTURE_BITS)}


@dataclass(frozen=True)
class KnockTicket:
    sid: str
    ticket_id: str
    expires_at: int
    wg_public_key: bytes
    posture: int = 0

    @property
    def signals(self) -> dict[str, bool]:
        """The posture byte as the trust scorer's signal dict."""
        return unpack_posture(self.posture)


def pack_body(sid: str, ticket_id: str, expires_at: int, wg_public_key: bytes,
              posture: int = 0) -> bytes:
    if len(wg_public_key) != WG_KEY_LEN:
        raise ValueError(f"WireGuard public key must be {WG_KEY_LEN} bytes, got {len(wg_public_key)}")
    if not 0 <= posture <= 0xFF:
        raise ValueError(f"posture must fit in one byte, got {posture}")
    return _BODY.pack(VERSION, uuid.UUID(sid).bytes, uuid.UUID(ticket_id).bytes,
                      expires_at, wg_public_key, posture)


def verify(ticket: bytes, public_key: ec.EllipticCurvePublicKey,
           now: float | None = None) -> KnockTicket:
    """Check length, version, signature and expiry. Single use is NOT checked
    here: that needs memory of spent ticket ids, which only the Gateway has."""
    if len(ticket) != TICKET_LEN:
        raise InvalidTicket(f"ticket must be {TICKET_LEN} bytes, got {len(ticket)}")
    body, signature = ticket[:_BODY.size], ticket[_BODY.size:]
    version, sid, ticket_id, expires_at, wg_key, posture = _BODY.unpack(body)
    if version != VERSION:
        raise InvalidTicket(f"unsupported ticket version {version}")
    try:
        public_key.verify(ecdsa_raw_to_der(signature), body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise InvalidTicket("ticket signature does not verify") from exc
    if (time.time() if now is None else now) > expires_at:
        raise InvalidTicket("ticket expired")
    # The posture byte is covered by the signature checked above, so the
    # caller may trust it exactly as far as it trusts the IDP.
    return KnockTicket(sid=str(uuid.UUID(bytes=sid)), ticket_id=str(uuid.UUID(bytes=ticket_id)),
                       expires_at=expires_at, wg_public_key=wg_key, posture=posture)
