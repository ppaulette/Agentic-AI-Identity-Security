"""Signing and strict verification of ES256 JWTs."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable

import jwt

from .keys import JWKS, KeyPair

ALGORITHMS = ["ES256"]  # pinned: never accept "none" or HMAC algorithms


class TokenError(Exception):
    """A token failed validation. The message is safe to return to the caller."""


def sign(claims: dict, key: KeyPair, typ: str = "JWT", extra_headers: dict | None = None) -> str:
    headers = {"kid": key.kid, "typ": typ, **(extra_headers or {})}
    return jwt.encode(claims, key.private_key, algorithm="ES256", headers=headers)


def new_claims(iss: str, sub: str, aud: str | list[str], ttl: int, **extra) -> dict:
    now = int(time.time())
    return {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        **extra,
    }


def verify(
    token: str,
    jwks: JWKS,
    *,
    issuer: str | Iterable[str],
    audience: str,
    typ: str | None = None,
    required: Iterable[str] = ("iss", "sub", "aud", "exp", "iat", "jti"),
    leeway: int = 0,
) -> dict:
    """Verify signature, algorithm, kid, typ, issuer, audience and expiry."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenError("malformed token") from exc
    if header.get("alg") not in ALGORITHMS:
        raise TokenError(f"algorithm {header.get('alg')!r} not allowed")
    if typ is not None and header.get("typ", "").lower() != typ.lower():
        raise TokenError(f"expected token type {typ!r}")
    kid = header.get("kid")
    if not kid or kid not in jwks:
        raise TokenError("unknown signing key")
    issuers = [issuer] if isinstance(issuer, str) else list(issuer)
    try:
        claims = jwt.decode(
            token,
            jwks.get(kid),
            algorithms=ALGORITHMS,
            audience=audience,
            options={"require": list(required), "verify_iss": False},
            leeway=leeway,
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError("token not issued for this audience") from exc
    except jwt.PyJWTError as exc:
        raise TokenError(f"invalid token: {exc}") from exc
    if claims.get("iss") not in issuers:
        raise TokenError("untrusted issuer")
    return claims
