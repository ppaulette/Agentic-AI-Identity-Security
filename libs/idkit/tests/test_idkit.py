import time

import jwt
import pytest

from idkit import (
    JWKS,
    KeyPair,
    ReplayCache,
    TokenError,
    jwk_thumbprint,
    make_proof,
    new_claims,
    sign,
    verify,
    verify_proof,
)


def test_rfc7638_thumbprint_example():
    # RFC 7638 uses an RSA example; this checks determinism and member selection for EC.
    key = KeyPair.generate()
    extra = dict(key.jwk, kid="other", use="enc")
    assert jwk_thumbprint(key.jwk) == jwk_thumbprint(extra)


def test_verify_round_trip_and_audience():
    key = KeyPair.generate("k1")
    jwks = JWKS([key.jwk])
    token = sign(new_claims("iss", "alice", "api", 60), key)
    assert verify(token, jwks, issuer="iss", audience="api")["sub"] == "alice"
    with pytest.raises(TokenError, match="audience"):
        verify(token, jwks, issuer="iss", audience="other-api")
    with pytest.raises(TokenError, match="issuer"):
        verify(token, jwks, issuer="evil", audience="api")


def test_rejects_alg_none_and_hmac():
    key = KeyPair.generate("k1")
    jwks = JWKS([key.jwk])
    claims = new_claims("iss", "alice", "api", 60)
    unsigned = jwt.encode(claims, None, algorithm="none", headers={"kid": "k1"})
    with pytest.raises(TokenError, match="not allowed"):
        verify(unsigned, jwks, issuer="iss", audience="api")
    hmac = jwt.encode(claims, "x" * 32, algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(TokenError, match="not allowed"):
        verify(hmac, jwks, issuer="iss", audience="api")


def test_rejects_expired_and_unknown_key():
    key = KeyPair.generate("k1")
    stranger = KeyPair.generate("k2")
    jwks = JWKS([key.jwk])
    claims = new_claims("iss", "alice", "api", 60)
    claims["exp"] = int(time.time()) - 5
    with pytest.raises(TokenError, match="expired"):
        verify(sign(claims, key), jwks, issuer="iss", audience="api")
    with pytest.raises(TokenError, match="unknown signing key"):
        verify(sign(new_claims("iss", "a", "api", 60), stranger), jwks, issuer="iss", audience="api")


def test_dpop_proof_binding_and_replay():
    key = KeyPair.generate()
    cache = ReplayCache()
    proof = make_proof(key, "POST", "https://rs.example/mcp", access_token="tok")
    jkt = verify_proof(
        proof,
        htm="POST",
        htu="https://rs.example/mcp",
        replay_cache=cache,
        access_token="tok",
        expected_jkt=key.thumbprint,
    )
    assert jkt == key.thumbprint
    with pytest.raises(TokenError, match="replayed"):
        verify_proof(proof, htm="POST", htu="https://rs.example/mcp", replay_cache=cache, access_token="tok")


@pytest.mark.parametrize(
    ("htm", "htu", "token", "jkt", "match"),
    [
        ("GET", "https://rs.example/mcp", "tok", None, "htm"),
        ("POST", "https://other.example/mcp", "tok", None, "htu"),
        ("POST", "https://rs.example/mcp", "different", None, "ath"),
        ("POST", "https://rs.example/mcp", "tok", "not-my-key", "cnf.jkt"),
    ],
)
def test_dpop_mismatches(htm, htu, token, jkt, match):
    key = KeyPair.generate()
    proof = make_proof(key, "POST", "https://rs.example/mcp", access_token="tok")
    with pytest.raises(TokenError, match=match):
        verify_proof(
            proof, htm=htm, htu=htu, replay_cache=ReplayCache(), access_token=token, expected_jkt=jkt
        )
