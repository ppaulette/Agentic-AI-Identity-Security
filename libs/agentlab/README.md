# agentlab

Builds the whole system in one process: mock IdP, SCIM server, broker, PDP and MCP gateway,
each on its own hostname over in-memory HTTP. Used by the gateway tests, the red-team suite
and `scripts/demo.py`.
