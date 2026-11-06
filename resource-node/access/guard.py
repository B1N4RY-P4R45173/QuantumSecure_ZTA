"""Turning an ``Authorization`` header into verified claims, entirely offline.

The resource node is on data-plane-net only. There is no route from here to
the IDP: no ``/.well-known/jwks.json`` fetch, no token introspection, no
retry. That is the point of the topology — the thing most exposed to a
compromised client must not be able to reach the identity store — and it
dictates the design of this module:

  * The IDP's RS256 PUBLIC key is read from a file at startup
    (``RESOURCE_JWT_PUBLIC_KEY_PATH``) and held in memory. Distributing a
    public key by file is safe in a way a shared secret never is: a copy of
    it mints nothing.

  * Loading FAILS CLOSED. A node that cannot verify a signature cannot make
    an authorization decision, so it refuses to start rather than start and
    refuse every request — the same posture the Gateway takes when the IDP
    serves it an empty JWKS. The checks here also reject a key of the wrong
    *kind*: the IDP keeps an ES256 knock-ticket key next to the RS256 JWT key
    in the same directory, and a path pointing at the wrong one must fail at
    startup with a clear message, not at 3am as an unexplained 401 storm.

  * ``algorithms`` is pinned to RS256 and nothing else. Letting PyJWT take
    the algorithm from the token header is the classic JWT break: ``alg:
    none`` strips verification, and ``alg: HS256`` invites the verifier to
    use the known public key as an HMAC secret, which anyone holding that
    public key can forge against. Pinning the list makes the token header's
    own claim about its algorithm irrelevant.

Everything that fails raises ``TokenRejected`` carrying a specific reason for
the audit trail. The caller turns every one of them into the same opaque 401.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from access.session_validator import (
    CLOCK_SKEW_LEEWAY_SECONDS,
    TokenRejected,
    audiences,
    validate,
)
from shared.ca.cert_utils import fingerprint
from shared.utils.logger import get_logger, status

log = get_logger("Res-Guard")

# The request header the contract names. Case-insensitive on the wire, and
# http.client's message object looks it up case-insensitively.
AUTH_HEADER = "Authorization"
BEARER_SCHEME = "bearer"

# Pinned, never read from the token header. See the module docstring.
ALGORITHMS = ["RS256"]

# Claims without which the token cannot be acted on at all: `exp` bounds it,
# `aud` says who it was for, `sub` is the identity the response reports and
# the audit trail records. PyJWT raises MissingRequiredClaimError for any
# absent one, before this module looks at a single value.
REQUIRED_CLAIMS = ["exp", "aud", "sub"]

# An RSA key below this is not a 2026 signing key. The IDP generates 2048-bit
# or larger (shared/utils/crypto.py); a smaller one in this file means
# someone substituted it.
MIN_RSA_KEY_BITS = 2048


@dataclass(frozen=True)
class TokenAuthority:
    """Everything needed to judge a token, resolved once at startup.

    Frozen and passed explicitly rather than kept in a module global: the
    server runs a thread per connection, and a value that cannot be rebound
    needs no lock.
    """

    public_key: RSAPublicKey
    audience: str
    key_path: str
    key_fingerprint: str


def load_authority(public_key_path: str, audience: str) -> TokenAuthority:
    """Read the IDP's RS256 public key and pin it for the process lifetime.

    Raises FileNotFoundError if the key is absent and ValueError if it is not
    a usable RSA public key. Both are fatal by design — see the module
    docstring — and main.py reports them and exits non-zero.
    """
    if not os.path.isfile(public_key_path):
        raise FileNotFoundError(
            f"IDP JWT public key not found at {public_key_path} - the resource node cannot "
            "verify tokens and will not start. Copy the IDP's public key here "
            "(IDENTITY_PROVIDER/certs/idp_jwt_public.pem) or set "
            "RESOURCE_JWT_PUBLIC_KEY_PATH.")

    with open(public_key_path, "rb") as handle:
        pem = handle.read()

    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:  # cryptography raises several unrelated types here
        raise ValueError(f"{public_key_path} is not a readable PEM public key: {exc}") from exc

    if not isinstance(key, RSAPublicKey):
        raise ValueError(
            f"{public_key_path} holds a {type(key).__name__}, not an RSA public key. The IDP "
            "signs access tokens with RS256; its ES256 key (idp_ticket_public.pem) signs knock "
            "tickets and cannot verify a JWT.")
    if key.key_size < MIN_RSA_KEY_BITS:
        raise ValueError(
            f"{public_key_path} holds a {key.key_size}-bit RSA key; "
            f"{MIN_RSA_KEY_BITS} is the minimum accepted.")

    # Same short fingerprint format the Gateway prints for its ML-KEM key, so
    # an operator can compare this against the IDP's key by eye on two
    # machines and confirm the resource is trusting the right issuer.
    der = key.public_bytes(encoding=serialization.Encoding.DER,
                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
    key_print = fingerprint(der)
    status(log, "IDP verification key loaded", path=public_key_path,
           alg="RS256", bits=key.key_size, fingerprint=key_print, audience=audience)
    return TokenAuthority(public_key=key, audience=audience,
                          key_path=public_key_path, key_fingerprint=key_print)


def extract_bearer(header_value: str | None) -> str:
    """Pull the token out of ``Authorization: Bearer <token>``.

    Split on whitespace rather than on a literal "Bearer " prefix: RFC 7235
    allows any amount of whitespace between scheme and credentials, and the
    scheme is case-insensitive. A header that is merely absent and one that
    is malformed are distinguished for the log, not for the client.
    """
    if header_value is None:
        raise TokenRejected("no Authorization header")
    parts = header_value.split(None, 1)
    if not parts:
        raise TokenRejected("empty Authorization header")
    if parts[0].lower() != BEARER_SCHEME:
        raise TokenRejected(f"Authorization scheme is {parts[0]!r}, not Bearer")
    if len(parts) == 1:
        raise TokenRejected("Bearer scheme with no credentials")
    token = parts[1].strip()
    if not token:
        raise TokenRejected("Bearer scheme with an empty token")
    return token


def decode(authority: TokenAuthority, token: str) -> dict:
    """Verify the signature and the structural claims. Audience is left out.

    ``verify_aud`` is off here and checked in session_validator instead, for
    one reason: PyJWT needs to be told a single expected audience, and the
    failure it raises does not say what the token actually claimed. Doing it
    by hand means the audit line can name both sides of the mismatch, which
    is what tells an operator whether a client is confused or something is
    replaying a Gateway token at a resource.
    """
    try:
        return jwt.decode(
            token,
            authority.public_key,
            algorithms=ALGORITHMS,
            leeway=CLOCK_SKEW_LEEWAY_SECONDS,
            options={"verify_aud": False, "require": REQUIRED_CLAIMS},
        )
    except jwt.ExpiredSignatureError:
        raise TokenRejected("token expired") from None
    except jwt.ImmatureSignatureError:
        raise TokenRejected("token not valid yet (nbf is in the future)") from None
    except jwt.MissingRequiredClaimError as exc:
        raise TokenRejected(f"token is missing a required claim: {exc.claim}") from None
    except jwt.InvalidSignatureError:
        # Subclass of DecodeError, so it must be caught before it. This is
        # the one that means forgery rather than fumbling.
        raise TokenRejected("signature does not verify against the pinned IDP key") from None
    except jwt.DecodeError as exc:
        raise TokenRejected(f"malformed token: {exc}") from None
    except jwt.InvalidAlgorithmError as exc:
        raise TokenRejected(f"token algorithm is not RS256: {exc}") from None
    except jwt.PyJWTError as exc:
        # Nothing should reach here; a new PyJWT error type must still deny.
        raise TokenRejected(f"rejected by PyJWT ({type(exc).__name__}): {exc}") from None


def authorize(authority: TokenAuthority, header_value: str | None) -> dict:
    """The whole decision: header -> token -> signature -> claims -> claims.

    Returns the verified claims. Raises TokenRejected, and only
    TokenRejected, for every way a request can fail to be authorized.
    """
    token = extract_bearer(header_value)
    claims = decode(authority, token)
    validate(claims, authority.audience)
    status(log, "Token accepted", sub=claims.get("sub"), sid=claims.get("sid"),
           jti=claims.get("jti"), iss=claims.get("iss"),
           aud=",".join(audiences(claims)), amr=claims.get("amr"),
           roles=claims.get("roles"), scope=claims.get("scope"))
    return claims
