"""EC P-256 key handling and RFC 7638 JWK thumbprints."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC public JWK (required members only, sorted, no spaces)."""
    if jwk.get("kty") != "EC":
        raise ValueError("only EC keys are supported")
    canonical = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    digest = hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode())
    return b64url(digest.digest())


def public_jwk(public_key: ec.EllipticCurvePublicKey, kid: str | None = None) -> dict:
    jwk = ECAlgorithm.to_jwk(public_key, as_dict=True)
    jwk = {k: jwk[k] for k in ("kty", "crv", "x", "y")}
    jwk["kid"] = kid or jwk_thumbprint(jwk)
    jwk["alg"] = "ES256"
    jwk["use"] = "sig"
    return jwk


def key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey | rsa.RSAPublicKey:
    """Load a public EC or RSA key from a JWK, refusing private material."""
    if any(k in jwk for k in ("d", "p", "q", "dp", "dq", "qi")):
        raise ValueError("refusing a JWK that contains private key material")
    if jwk.get("kty") == "EC":
        key = ECAlgorithm.from_jwk({k: jwk[k] for k in ("kty", "crv", "x", "y")})
        if isinstance(key, ec.EllipticCurvePublicKey):
            return key
    elif jwk.get("kty") == "RSA":
        key = RSAAlgorithm.from_jwk({k: jwk[k] for k in ("kty", "n", "e")})
        if isinstance(key, rsa.RSAPublicKey):
            return key
    raise ValueError("expected an EC or RSA public key")


@dataclass
class KeyPair:
    """An ES256 signing key with its public JWK."""

    private_key: ec.EllipticCurvePrivateKey
    kid: str = ""
    jwk: dict = field(init=False)

    def __post_init__(self) -> None:
        self.jwk = public_jwk(self.private_key.public_key(), self.kid or None)
        self.kid = self.jwk["kid"]

    @classmethod
    def generate(cls, kid: str = "") -> KeyPair:
        return cls(ec.generate_private_key(ec.SECP256R1()), kid)

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.jwk)

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @classmethod
    def from_pem(cls, pem: bytes, kid: str = "") -> KeyPair:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("expected an EC private key")
        return cls(key, kid)


class JWKS:
    """A set of trusted public keys, looked up by kid."""

    def __init__(self, keys: list[dict] | None = None) -> None:
        self._keys: dict[str, dict] = {}
        for jwk in keys or []:
            self.add(jwk)

    def add(self, jwk: dict) -> None:
        self._keys[jwk["kid"]] = jwk

    @classmethod
    def from_spiffe_bundle(cls, bundle: dict) -> JWKS:
        """Keep only the JWT-SVID signing keys from a SPIFFE bundle (JWKS format)."""
        return cls([k for k in bundle.get("keys", []) if k.get("use") == "jwt-svid" and k.get("kid")])

    def get(self, kid: str) -> ec.EllipticCurvePublicKey | rsa.RSAPublicKey:
        if kid not in self._keys:
            raise KeyError(f"unknown kid {kid!r}")
        return key_from_jwk(self._keys[kid])

    def __contains__(self, kid: str) -> bool:
        return kid in self._keys

    def as_dict(self) -> dict:
        return {"keys": list(self._keys.values())}
