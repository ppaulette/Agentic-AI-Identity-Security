# 02 · AuthZEN policy decision point for agent tool calls

An implementation of the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
access evaluation endpoints. The [MCP gateway](../04-mcp-auth-gateway) asks it before **every**
tool call: *may this agent, acting for this user, call this tool with these arguments, now?*

## Policy

Deny by default. Rules run in order; the first that fails decides, and every decision returns
a reason and the rule name for the audit log.

| Rule | Denies when |
|---|---|
| `known-tool` | the tool is not in the catalogue |
| `agent-forbidden` | the tool is never callable by agents (`admin.export_users`) |
| `delegation-required` | an agent call carries no `acting_for` user |
| `scope` | the token lacks the tool's scope |
| `step-up-approval` | a high-risk tool has no bound human approval |
| `device` | (optional) a high-risk call comes from a device whose posture is not `compliant` |
| `amount-limit` | arguments exceed a tool's limit (refunds over $500) |

The policy lives in [`policy.json`](src/authzen_pdp/policy.json).

## Example

```bash
curl -s localhost:8002/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type": "agent", "id": "agent:helpdesk-bot",
               "properties": {"acting_for": "user:alice", "scopes": ["tickets.read"]}},
  "action":   {"name": "tools/call"},
  "resource": {"type": "tool", "id": "admin.export_users"},
  "context":  {}
}'
# {"decision": false, "context": {"reason": "admin.export_users is never callable by agents", "rule": "agent-forbidden"}}
```

Run locally with `uv run uvicorn authzen_pdp.app:app --port 8002`.

Also implemented: `POST /access/v1/evaluations` (batch, with top-level defaults) and
`GET /.well-known/authzen-configuration`.

## Next

Express the same policy in Cedar and in OPA/Rego behind this API, and compare.
