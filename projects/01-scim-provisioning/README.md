# 01 · SCIM provisioning that revokes agent access

A SCIM 2.0 `Users` endpoint (RFC 7643/7644) that an IdP such as Okta or Entra ID can provision
into. Its job in this system: **when a person is deactivated or deleted, every AI agent acting
for them loses access immediately**, not when their tokens happen to expire.

On `PATCH active=false` (both the Okta value-object style and the Entra `path` style), `PUT`
with `active: false`, or `DELETE`, the server sends `POST /events/user-deprovisioned` to the
[Agent Identity Broker](../03-agent-identity-broker). The broker stops issuing tokens for that
user and reports their live tokens as inactive to the [MCP gateway](../04-mcp-auth-gateway).

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/scim/v2/ServiceProviderConfig` | Advertises PATCH and filter support |
| POST | `/scim/v2/Users` | `userName` uniqueness (409 `uniqueness`) |
| GET | `/scim/v2/Users?filter=userName eq "x"` | The filter IdPs use before creating users |
| GET / PUT / PATCH / DELETE | `/scim/v2/Users/{id}` | Deprovisioning notifies the broker once |

Errors use the SCIM error schema with `scimType`. Requests need the IdP's bearer token,
compared in constant time.

## Try it

```bash
uv run pytest projects/01-scim-provisioning
```

## Not implemented

Groups, Bulk, ETags, complex filters. A production version would sign events (for example as
Security Event Tokens, RFC 8417) instead of using a shared secret.
