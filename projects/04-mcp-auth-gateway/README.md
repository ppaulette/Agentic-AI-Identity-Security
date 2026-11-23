# 04 · MCP auth gateway

An MCP server (JSON-RPC over HTTP: `initialize`, `tools/list`, `tools/call`) built as an OAuth
2.x resource server, following the MCP authorization spec. It fronts a small help-desk system
with four tools of increasing risk, one of which holds a prompt-injection payload.

## What happens on every request

1. **Discovery.** Without a valid token it answers `401` with
   `WWW-Authenticate: DPoP resource_metadata="…/.well-known/oauth-protected-resource"` so a
   client can find the authorization server (RFC 9728).
2. **Token.** ES256 signature against the broker's JWKS (re-fetched on unknown `kid` for key
   rotation), issuer, audience = this server, expiry, `typ=at+jwt`.
3. **Proof of possession.** DPoP proof for this method and URL, with `ath` matching the token,
   key matching `cnf.jkt`, fresh `iat`, unused `jti`.
4. **Liveness.** Introspection at the broker, so deprovisioned users and disabled agents stop
   at once.
5. **Authorization.** For `tools/call`, an AuthZEN evaluation with the agent, the user, the
   token's scopes, the arguments and whether a human approved it. `tools/list` only shows tools
   the token's scopes cover.
6. **Human approval.** High-risk tools need an approval created by an approver, bound to that
   user and tool, used once.

Missing scope returns `403` with `error="insufficient_scope"` and the needed `scope`, which an
MCP client can use to step up. Policy denials return a JSON-RPC error with the PDP's reason.
Every call is audited with user, agent, tool, decision and reason.

## Tools

| Tool | Scope | Risk |
|---|---|---|
| `tickets.read` | `tickets.read` | low (ticket T-200 contains an injected instruction) |
| `tickets.comment` | `tickets.write` | low |
| `payments.refund` | `payments.refund` | high: approval required, $500 limit |
| `admin.export_users` | `admin.export` | critical: never callable by agents |

## Tests

```bash
uv run pytest projects/04-mcp-auth-gateway
```

Note: this implements the subset of MCP needed to demonstrate authorization. It does not use
the official MCP SDK or support sessions, streaming or notifications.
