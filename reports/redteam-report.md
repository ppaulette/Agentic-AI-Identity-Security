# Red-team report: agent identity stack

Generated 2026-11-24 08:16 UTC by `python -m redteam`. **21 of 21 attacks blocked.**

| ID | Attack | Threat | Result | Control that stopped it | Evidence |
|---|---|---|---|---|---|
| A01 | Stolen access token used without the DPoP key | Token theft (OAuth) | Blocked | DPoP binding (cnf.jkt) | `HTTP 401: DPoP key does not match the token's cnf.jkt` |
| A02 | Stolen DPoP token presented as a plain Bearer token | Token theft (OAuth) | Blocked | DPoP scheme required | `HTTP 401: DPoP-bound access token required` |
| A03 | Captured request replayed with the same DPoP proof | Replay | Blocked | DPoP jti replay cache | `HTTP 401: DPoP proof replayed` |
| A04 | Genuine token issued for another API presented here | Token misuse across services | Blocked | Audience check (aud = this resource) | `HTTP 401: token not issued for this audience` |
| A05 | Captured token used after it expired | Token replay | Blocked | Expiry check (5-minute tokens) | `HTTP 401: token expired` |
| A06 | Unsigned token (alg=none) claiming admin scope | Token forgery | Blocked | Algorithm pinned to ES256 | `HTTP 401: algorithm 'none' not allowed` |
| A07 | Forged act claim to impersonate a more trusted agent | Agent impersonation | Blocked | Signature check against broker JWKS | `HTTP 401: invalid token: Signature verification failed` |
| A08 | Attacker presents a stolen agent ID with their own key | Agent impersonation | Blocked | private_key_jwt client authentication | `HTTP 401: agent authentication failed: invalid token: Signature verification failed` |
| A09 | Captured agent assertion replayed at the token endpoint | Replay | Blocked | Actor assertion jti replay cache | `HTTP 401: actor assertion replayed` |
| A10 | Agent requests scopes beyond the user's role | Excessive agency / privilege expansion | Blocked | Scope intersection at the broker | `granted only: tickets.read` |
| A11 | Agent requests a token for a resource it is not registered for | Confused deputy | Blocked | Resource indicator allow-list (RFC 8707) | `HTTP 400: agent is not registered for this resource` |
| A12 | Forged ID token from a look-alike IdP | Identity provider spoofing | Blocked | IdP JWKS pinning | `HTTP 400: subject token rejected: invalid token: Signature verification failed` |
| A13 | Prompt injection in a ticket makes the agent export all users | Prompt injection → tool misuse (LLM01, LLM06) | Blocked | Agent-forbidden tool policy + scope | `HTTP 403: admin.export_users is never callable by agents` |
| A14 | Agent issues a refund with no human approval | Excessive agency (LLM06) | Blocked | Step-up human approval | `HTTP 403: payments.refund needs human approval` |
| A15 | Approval for $40 reused for $4,000 | Unsafe delegation | Blocked | Single-use approvals | `HTTP 403: payments.refund needs human approval` |
| A16 | Approved refund above the policy limit | Excessive agency (LLM06) | Blocked | Amount limit in policy | `HTTP 403: amount 4000 exceeds limit 500` |
| A17 | User is deprovisioned while their agent holds a live token | Orphaned access | Blocked | SCIM → broker revocation + introspection | `HTTP 401: token is no longer active` |
| A18 | Compromised agent keeps using its token | Compromised agent | Blocked | Agent kill switch + introspection | `HTTP 401: token is no longer active` |
| A19 | SVID signed by a rogue SPIRE server for the same trust domain | Workload identity spoofing | Blocked | Trust bundle pinning | `HTTP 401: SVID rejected: invalid token: Signature verification failed` |
| A20 | Genuine SVID for another service replayed at the broker | Token misuse across services | Blocked | SVID audience = broker token endpoint | `HTTP 401: SVID rejected: token not issued for this audience` |
| A21 | Unregistered workload in the trust domain tries to act as an agent | Excessive agency / privilege expansion | Blocked | SPIFFE ID to agent registration mapping | `HTTP 401: no agent registered for this SPIFFE ID` |
