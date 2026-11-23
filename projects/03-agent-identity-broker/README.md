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
| Agent signed the actor assertion with its registered key; assertion not replayed | RFC 7523 (`private_key_jwt`) | `invalid_client` |
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
