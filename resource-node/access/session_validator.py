"""The claim checks a resource node can make with nothing but a clock.

This node sits on data-plane-net and has no route to the IDP. It cannot
introspect a token, cannot refresh a JWKS, and cannot ask anyone whether a
session is still alive. So everything it is allowed to believe must either be
signed into the token — access/guard.py verifies that signature against the
IDP's public key read from disk — or be derivable from the token's own
claims, which is this module.

Two claims decide it:

  * ``aud`` must name this resource tier. The IDP mints ONE access token
    whose audience names both the Gateway and the resources
    (``["sdp-gateway", "resource-node"]`` — see
    IDENTITY_PROVIDER/tokens/jwt_service.py), precisely so each hop can
    re-check that it was in fact an intended recipient. Per RFC 7519 4.1.3
    the claim is either a string or a list of strings, and both shapes occur
    here: the IDP's access token carries a list, its login and refresh tokens
    carry a string. Both are accepted, and a login or refresh token
    presented here therefore fails on audience rather than on signature.

  * ``exp`` must be in the future. The lease IS the revocation story for this
    node: when the Controller tears a session down, the Gateway closes the
    pinhole and nothing at all reaches the resource — but no message does,
    either. A token that outlived its session stays cryptographically valid
    until ``exp``, so a short expiry is the whole bound on the damage.

``TokenRejected`` lives here, not in guard.py, because both modules raise it
and the import runs guard -> session_validator. It deliberately keeps the
operator-facing ``reason`` apart from anything the client is told: the audit
line names the exact check that failed, the HTTP body never does.
"""

from __future__ import annotations

import time
from typing import Any

from shared.utils.logger import get_logger, status

log = get_logger("Res-Token")

# No grace period on expiry. PyJWT's `leeway` would accept a token for N
# seconds past `exp`, and `exp` is the only revocation signal that ever
# reaches this node. A node whose clock has drifted should have its clock
# fixed, not its validity window silently widened. Named rather than inlined
# so the decision is visible, and so guard.py passes the same value to PyJWT
# as this module applies to its own check.
CLOCK_SKEW_LEEWAY_SECONDS = 0


class TokenRejected(Exception):
    """A presented token failed one of the checks.

    ``reason`` is for the audit trail only. The request handler answers 401
    with a fixed, generic body, so a prober cannot use the response to learn
    which check failed — whether a signature was forged, a token merely
    stale, or an audience merely wrong. That distinction is operator
    information; it goes to the log.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def audiences(claims: dict[str, Any]) -> tuple[str, ...]:
    """``aud`` normalised to a tuple of strings.

    Returns an empty tuple for a missing, null or wrongly-typed claim, so
    every caller fails closed on it instead of having to re-check the shape.
    Non-string members of a list are dropped rather than coerced: an audience
    is an identifier, and ``str()`` of an arbitrary object is not one.
    """
    raw = claims.get("aud")
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, (list, tuple)):
        return tuple(member for member in raw if isinstance(member, str))
    return ()


def check_audience(claims: dict[str, Any], expected: str) -> None:
    """``expected`` must appear in ``aud``. Raises TokenRejected otherwise."""
    present = audiences(claims)
    if not present:
        raise TokenRejected("token carries no usable aud claim")
    if expected not in present:
        # The presented audiences are safe to log: they came out of a token
        # whose signature already verified, so they are the IDP's words.
        raise TokenRejected(
            f"aud does not name this resource (expected {expected!r}, got {list(present)})")


def check_expiry(claims: dict[str, Any], now: float | None = None) -> None:
    """``exp`` must be present, numeric and still in the future.

    PyJWT already enforces expiry during decode; this repeats the check on
    purpose. It is the one claim that must never be optional here, and
    re-deriving it from the claims means a future change to the decode
    options cannot quietly turn expiry off. ``bool`` is excluded explicitly
    because ``isinstance(True, int)`` is true in Python, and ``exp: true``
    would otherwise read as the epoch second 1.
    """
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise TokenRejected("token has no numeric exp claim")
    now = time.time() if now is None else now
    if now - CLOCK_SKEW_LEEWAY_SECONDS >= exp:
        raise TokenRejected(f"token expired {now - exp:.0f}s ago")


def validate(claims: dict[str, Any], expected_audience: str,
             now: float | None = None) -> None:
    """Run every claim check. Raises TokenRejected on the first failure.

    Audience before expiry, so the log says "wrong recipient" rather than
    "stale" for a token that is both — the former is the more interesting
    event, because it means something presented a token minted for another
    hop.
    """
    check_audience(claims, expected_audience)
    check_expiry(claims, now)
    status(log, "Claims accepted", sub=claims.get("sub"), sid=claims.get("sid"),
           aud=",".join(audiences(claims)), acr=claims.get("acr"),
           remaining=f"{claims['exp'] - (time.time() if now is None else now):.0f}s")
