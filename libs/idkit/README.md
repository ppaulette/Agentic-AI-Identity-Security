# idkit

Small, strict JOSE helpers shared by every project here.

- `KeyPair`, `JWKS`, `jwk_thumbprint` (RFC 7638): ES256 keys and key sets; refuses JWKs with private material.
- `sign` / `verify`: algorithm pinned to ES256 (no `none`, no HMAC confusion), required claims, `typ` check, unknown `kid` rejected.
- `make_proof` / `verify_proof` (RFC 9449): DPoP with `htm`, `htu`, `ath`, `iat` window, `cnf.jkt` match and a replay cache.
- `AuditLog`: structured events, optionally to JSONL.
- `MockIdP`: stands in for Okta/Entra in tests and the demo.
