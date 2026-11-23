"""A stand-in enterprise IdP that issues OIDC ID tokens for test users.

In a real deployment this is Okta, Entra ID or another OIDC provider; the broker
only needs its issuer and JWKS.
"""

from __future__ import annotations

from .keys import JWKS, KeyPair
from .tokens import new_claims, sign


class MockIdP:
    def __init__(self, issuer: str = "https://idp.example.test") -> None:
        self.issuer = issuer
        self.key = KeyPair.generate(kid="idp-1")

    @property
    def jwks(self) -> JWKS:
        return JWKS([self.key.jwk])

    def id_token(self, sub: str, audience: str, roles: list[str], ttl: int = 600) -> str:
        claims = new_claims(self.issuer, sub, audience, ttl, roles=roles, email=f"{sub}@example.test")
        return sign(claims, self.key, typ="JWT")
