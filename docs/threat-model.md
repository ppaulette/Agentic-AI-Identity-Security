# Threat model

Scope: an AI agent that calls tools through MCP on behalf of enterprise users. Method: STRIDE
per trust boundary, then mapped to OWASP Top 10 for LLM Applications (2025) where relevant.
Every mitigation listed as "tested" has an attack in
[projects/05-agent-redteam](../projects/05-agent-redteam) that fails in CI if the control
breaks.

## Assets

- Users' authority (what they may do in downstream systems)
- Agent credentials (signing key, DPoP key, access tokens)
- Tool side effects (refunds, data exports)
- The audit trail

## Trust boundaries

1. Agent ↔ Broker (token endpoint)
2. Agent ↔ MCP gateway (tool calls)
3. Gateway ↔ Broker (introspection) and Gateway ↔ PDP (decisions)
4. IdP ↔ SCIM server ↔ Broker (lifecycle events)
5. Untrusted content ↔ Agent (ticket text, web pages, tool output)

## Threats and controls

| # | STRIDE | Threat | Control | Status |
|---|---|---|---|---|
| T1 | Spoofing | Attacker claims to be a registered agent | private_key_jwt actor assertion verified against the registered key | Tested (A08) |
| T2 | Spoofing | Forged user identity from a look-alike IdP | IdP JWKS pinned; issuer and signature checked | Tested (A12) |
| T3 | Spoofing | Forged or unsigned access token | ES256 pinned, `alg=none` and HMAC rejected, `kid` must be known, `typ=at+jwt` | Tested (A06, A07) |
| T4 | Tampering | Agent or attacker edits `act`, `scope` or `aud` | Signature over all claims | Tested (A07) |
| T5 | Repudiation | Agent action cannot be tied to a user | `sub` + `act.sub` in every token; audit event per issuance and per tool call with decision and reason | Demonstrated in demo |
| T6 | Info disclosure | Token leaks through logs, memory or prompt injection | DPoP binding; 5-minute lifetime; audience restriction | Tested (A01, A02, A04, A05) |
| T7 | Info disclosure | Resource server learns other services' tokens | Introspection limited to tokens whose `aud` is the caller | Unit-tested |
| T8 | Elevation | Agent requests more than the user may do | Scope = requested ∩ agent ∩ user roles | Tested (A10) |
| T9 | Elevation | Agent gets a token for an unrelated API (confused deputy) | Resource indicator allow-list per agent (RFC 8707) | Tested (A11) |
| T10 | Elevation | Prompt injection drives a dangerous tool call (LLM01 → LLM06) | Agent-forbidden tools; scope check; PDP on every call; tools/list filtered by scope | Tested (A13) |
| T11 | Elevation | Agent performs a high-impact action unsupervised (LLM06) | Step-up human approval, amount limits | Tested (A14, A16) |
| T12 | Elevation | Approval reused for another user, tool or amount | Approval bound to user + tool, single-use | Tested (A15), unit-tested |
| T13 | Replay | Captured request or assertion replayed | `jti` replay caches for DPoP proofs and actor assertions; proof `iat` window | Tested (A03, A09) |
| T14 | Elevation | Access survives offboarding (orphaned agent access) | SCIM deactivation → broker revocation → introspection fails | Tested (A17) |
| T15 | Elevation | Compromised agent keeps working | Per-agent kill switch enforced by introspection and token endpoint | Tested (A18) |
| T16 | DoS | Token endpoint or PDP flooded | Not addressed in the lab; rate limiting at the edge | Open |
| T17 | Spoofing | Agent private key stolen from disk | SPIFFE JWT-SVIDs: short-lived, attested, no stored key (broker side, plus live SPIRE on Kubernetes); hardware-backed keys for laptop agents (roadmap 08) | Tested for cluster agents (A19–A21, live lab 6b); open for laptop agents |
| T18 | Tampering | Shared service secrets stolen | Not addressed in the lab; mTLS between services (roadmap 06) | Open |

## Residual risk

- **Allowed-but-harmful calls.** If a user may comment on tickets, an injected agent can post
  misleading comments within that permission. Authorization limits blast radius; it does not
  judge intent. Output filtering and human review of agent-authored content remain needed.
- **Approver fatigue.** Step-up only helps if approvers read what they approve. The approval
  should show the exact tool, arguments and the ticket that triggered it.
- **Policy drift.** Policy is code; it needs review and tests (see the PDP tests) like any code.
