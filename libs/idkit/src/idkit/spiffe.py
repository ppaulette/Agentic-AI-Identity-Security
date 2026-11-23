"""SPIFFE helpers: a stand-in SPIRE server for tests, and a bundle fetcher for live runs."""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx

from .keys import JWKS, KeyPair
from .tokens import sign


class MockSpire:
    """Issues JWT-SVIDs the way a SPIRE server does: sub = SPIFFE ID, aud, exp, no iss."""

    def __init__(self, trust_domain: str = "example.org") -> None:
        self.trust_domain = trust_domain
        self.key = KeyPair.generate(kid=f"spire-{trust_domain}")

    def bundle(self) -> dict:
        """The trust bundle in SPIFFE JWKS form (only the JWT-SVID key here)."""
        return {"keys": [dict(self.key.jwk, use="jwt-svid")], "spiffe_sequence": 1}

    def jwks(self) -> JWKS:
        return JWKS.from_spiffe_bundle(self.bundle())

    def jwt_svid(self, path: str, audience: str, ttl: int = 300) -> str:
        now = int(time.time())
        claims = {
            "sub": f"spiffe://{self.trust_domain}{path}",
            "aud": [audience],
            "iat": now,
            "exp": now + ttl,
        }
        return sign(claims, self.key, typ="JWT")

    def source(self, path: str) -> Callable[[str], str]:
        """A callable an agent can use as its SVID source, like the Workload API."""
        return lambda audience: self.jwt_svid(path, audience)


class BundleFetcher:
    """Fetch and cache JWT-SVID keys from a SPIRE OIDC discovery provider's JWKS URL."""

    def __init__(self, jwks_url: str, http: httpx.Client | None = None, ttl: int = 300) -> None:
        self.jwks_url, self.http, self.ttl = jwks_url, http or httpx.Client(timeout=5), ttl
        self._cached: JWKS | None = None
        self._fetched = 0.0

    def __call__(self) -> JWKS:
        if self._cached is None or time.time() - self._fetched > self.ttl:
            body = self.http.get(self.jwks_url).json()
            # The OIDC discovery provider serves plain JWKS (use=sig); bundles use use=jwt-svid.
            keys = [
                k for k in body.get("keys", []) if k.get("kid") and k.get("use") in (None, "sig", "jwt-svid")
            ]
            self._cached, self._fetched = JWKS(keys), time.time()
        return self._cached
