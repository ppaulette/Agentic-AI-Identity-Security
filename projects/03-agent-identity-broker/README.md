# 03 · Agent Identity Broker

An authorization server with one job: let an AI agent **act on behalf of a user** with a token
that is short-lived, narrowly scoped, tied to one API, and useless if stolen.

```
agent ──(user's ID token + agent's signed assertion + DPoP proof)──▶ broker
broker ──(5-minute at+jwt: sub=user, act=agent, aud=API, cnf.jkt=agent key)──▶ agent
```

## What it checks on `POST /token`

| Check | Standard | Error if it fails |
|---|---|---|
| DPoP proof is valid, fresh, unused | RFC 9449 | `invalid_dpop_proof` |
| Agent proves its identity: a JWT-SVID from the SPIFFE trust domain (no stored key), or an assertion signed with its registered key; not replayed | SPIFFE JWT-SVID, or RFC 7523 (`private_key_jwt`) | `invalid_client` |
| Agent is not disabled (kill switch) | — | `invalid_client` |
| User's ID token is from the trusted IdP and not expired | OIDC | `invalid_grant` |
| User is not deprovisioned | — | `invalid_grant` |
| Resource is one this agent is registered for | RFC 8707 | `invalid_target` |
| Granted scope = requested ∩ agent registration ∩ user's roles, and not empty | RFC 8693 | `invalid_scope` |

The issued token is an RFC 9068 `at+jwt` with `sub` (user), `act.sub` (agent), `aud`
(resource), `scope`, `cnf.jkt` (DPoP key thumbprint) and a 5-minute `exp`. Every issuance and
denial is written to the audit log, including which requested scopes were dropped.

## Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET /jwks.json` | Broker public keys |
| `POST /introspect` | RFC 7662; a resource server can only introspect tokens issued for itself |
| `POST /events/user-deprovisioned` | Called by the SCIM server |
| `POST /events/agent-disabled` | Kill switch for a compromised agent |

## CLI

```bash
uv run aib keygen --agent-id agent:helpdesk-bot --out keys   # prints the public JWK to register
uv run aib token --broker https://broker.example --agent-id agent:helpdesk-bot \
    --key keys/agent_helpdesk-bot.pem --subject-token-file alice.jwt \
    --resource https://mcp.tickets.example/mcp --scope tickets.read tickets.write
uv run aib decode <jwt>
```

The agent side lives in [`client.py`](src/agent_broker/client.py): `AgentClient.exchange()` for
tokens and `AgentClient.call_tool()` for DPoP-signed MCP calls.

## Tests

```bash
uv run pytest projects/03-agent-identity-broker
```

## Workload identity (SPIFFE)

An agent that runs as a SPIFFE workload doesn't need a registered key. It fetches a JWT-SVID
from the SPIRE agent (audience = the broker's token endpoint) and sends it as the
`actor_token`. The broker:

1. checks the SPIFFE ID is in its configured trust domain,
2. verifies the SVID against that trust domain's bundle keys (no `iss` in JWT-SVIDs, so the
   bundle is the trust anchor), with `aud` = the token endpoint,
3. maps the SPIFFE ID to an agent registration; unregistered workloads are refused.

```python
AgentRegistration(
    "agent:triage-bot",
    None,
    "team:support",
    {"tickets.read"},
    {RS},
    spiffe_id="spiffe://corp.example/ns/agents/sa/triage-bot",
)
BrokerConfig(
    ..., spiffe_trust_domain="corp.example", spiffe_bundle=BundleFetcher("https://oidc.corp.example/keys")
)
```

The audit event records `agent_auth` (`jwt-svid` or `private_key_jwt`) and the SPIFFE ID.
