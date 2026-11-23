"""DPoP proofs (RFC 9449): bind an access token to a key the agent holds."""

from __future__ import annotations

import hashlib
import threading
import time
import uuid

import jwt

from .keys import KeyPair, b64url, jwk_thumbprint, key_from_jwk
from .tokens import TokenError

MAX_PROOF_AGE = 60  # seconds


def access_token_hash(access_token: str) -> str:
    return b64url(hashlib.sha256(access_token.encode()).digest())


def make_proof(key: KeyPair, htm: str, htu: str, access_token: str | None = None) -> str:
    jwk = {k: key.jwk[k] for k in ("kty", "crv", "x", "y")}
    claims = {"jti": str(uuid.uuid4()), "htm": htm.upper(), "htu": htu, "iat": int(time.time())}
    if access_token is not None:
        claims["ath"] = access_token_hash(access_token)
    return jwt.encode(claims, key.private_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})


class ReplayCache:
    """Remembers jti values until they expire, so a proof or assertion is usable once."""

    def __init__(self, ttl: int = 300) -> None:
        self.ttl = ttl
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_store(self, jti: str) -> bool:
        """Return True the first time a jti is seen, False on replay."""
        now = time.time()
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            if jti in self._seen:
                return False
            self._seen[jti] = now + self.ttl
            return True


def verify_proof(
    proof: str,
    *,
    htm: str,
    htu: str,
    replay_cache: ReplayCache,
    access_token: str | None = None,
    expected_jkt: str | None = None,
) -> str:
    """Validate a DPoP proof and return the RFC 7638 thumbprint of its key."""
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as exc:
        raise TokenError("malformed DPoP proof") from exc
    if header.get("typ") != "dpop+jwt":
        raise TokenError("DPoP proof must have typ dpop+jwt")
    if header.get("alg") != "ES256":
        raise TokenError("DPoP proof algorithm not allowed")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise TokenError("DPoP proof missing jwk")
    try:
        public_key = key_from_jwk(jwk)
        claims = jwt.decode(
            proof,
            public_key,
            algorithms=["ES256"],
            options={"require": ["jti", "htm", "htu", "iat"], "verify_aud": False},
        )
    except (ValueError, jwt.PyJWTError) as exc:
        raise TokenError(f"invalid DPoP proof: {exc}") from exc

    if claims["htm"].upper() != htm.upper():
        raise TokenError("DPoP htm mismatch")
    if claims["htu"].split("?")[0].split("#")[0] != htu:
        raise TokenError("DPoP htu mismatch")
    if abs(time.time() - claims["iat"]) > MAX_PROOF_AGE:
        raise TokenError("DPoP proof is stale")
    if access_token is not None and claims.get("ath") != access_token_hash(access_token):
        raise TokenError("DPoP ath does not match the access token")
    jkt = jwk_thumbprint(jwk)
    if expected_jkt is not None and jkt != expected_jkt:
        raise TokenError("DPoP key does not match the token's cnf.jkt")
    if not replay_cache.check_and_store(claims["jti"]):
        raise TokenError("DPoP proof replayed")
    return jkt
