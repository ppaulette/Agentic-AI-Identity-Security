import pytest

from agentlab import MCP, build_lab


@pytest.fixture
def lab():
    return build_lab()


def text(response):
    return response.json()["result"]["content"][0]["text"]


def test_protected_resource_metadata(lab):
    meta = lab.gateway.get("/.well-known/oauth-protected-resource").json()
    assert meta["resource"] == MCP
    assert meta["authorization_servers"] == ["https://broker.example.test"]
    assert meta["dpop_bound_access_tokens_required"] is True


def test_unauthenticated_request_gets_discovery_challenge(lab):
    r = lab.gateway.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 401
    assert (
        'resource_metadata="https://mcp.tickets.example/.well-known/oauth-protected-resource"'
        in r.headers["www-authenticate"]
    )


def test_initialize_and_list_only_permitted_tools(lab):
    token = lab.token("alice", ["support"], ["tickets.read"])
    init = lab.agent.rpc(MCP, token, "initialize", gateway=lab.gateway).json()
    assert init["result"]["serverInfo"]["name"] == "helpdesk-mcp"
    tools = lab.agent.rpc(MCP, token, "tools/list", gateway=lab.gateway).json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["tickets.read"]


def test_allowed_call_and_audit(lab):
    token = lab.token("alice", ["support"], ["tickets.read"])
    r = lab.call(token, "tickets.read", {"ticket_id": "T-100"})
    assert r.status_code == 200 and "VPN" in text(r)
    entry = lab.audit.find("mcp.tool_call")[-1]
    assert entry == entry | {
        "user": "user:alice",
        "agent": "agent:helpdesk-bot",
        "tool": "tickets.read",
        "decision": "allow",
    }


def test_missing_scope_returns_step_up_challenge(lab):
    token = lab.token("alice", ["support"], ["tickets.read"])
    r = lab.call(token, "tickets.comment", {"ticket_id": "T-100", "text": "hi"})
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]
    assert 'scope="tickets.write"' in r.headers["www-authenticate"]


def test_high_risk_call_needs_single_use_bound_approval(lab):
    token = lab.token("frank", ["finance"], ["payments.refund"])
    args = {"ticket_id": "T-200", "amount": 40}
    assert lab.call(token, "payments.refund", args).status_code == 403

    wrong_user = lab.approve("alice", "payments.refund")
    assert lab.call(token, "payments.refund", args, wrong_user).status_code == 403

    approval = lab.approve("frank", "payments.refund")
    r = lab.call(token, "payments.refund", args, approval)
    assert r.status_code == 200 and "refunded $40" in text(r)
    assert lab.call(token, "payments.refund", args, approval).status_code == 403  # used up


def test_approvals_require_approver_credential(lab):
    r = lab.gateway.post("/approvals", json={"user": "user:x", "tool": "payments.refund", "approver": "me"})
    assert r.status_code == 403
