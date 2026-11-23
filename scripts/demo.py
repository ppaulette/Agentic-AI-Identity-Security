"""End-to-end walkthrough: one help-desk agent, two users, one poisoned ticket.

Run with:  uv run python scripts/demo.py
"""

from __future__ import annotations

import json

import jwt

from agentlab import MCP, build_lab


def step(title: str) -> None:
    print(f"\n\033[1m── {title}\033[0m")


def show(label: str, value) -> None:
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    print(f"{label}: {text}")


def outcome(response) -> str:
    body = response.json()
    if response.status_code == 200 and "result" in body:
        content = body["result"].get("content")
        return f"200 OK → {content[0]['text'].splitlines()[0]}" if content else "200 OK"
    reason = body.get("error_description") or body.get("error", {}).get("data", {}).get("reason")
    return f"{response.status_code} DENIED → {reason}"


def main() -> None:
    lab = build_lab()

    step("1. Alice (support) is provisioned by the IdP over SCIM")
    alice_scim_id = lab.provision("alice")
    show("SCIM user id", alice_scim_id)

    step("2. The help-desk agent exchanges Alice's ID token for a delegated token (RFC 8693)")
    result = lab.agent.exchange(
        lab.id_token("alice", ["support"]), MCP, ["tickets.read", "tickets.write", "payments.refund"]
    )
    token = result["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    show("requested", "tickets.read tickets.write payments.refund")
    show("granted  ", result["scope"] + "   (payments.refund dropped: Alice's role cannot grant it)")
    show("token claims", {k: claims[k] for k in ("sub", "act", "aud", "scope", "cnf", "exp")})

    step("3. The agent reads a normal ticket")
    print(outcome(lab.call(token, "tickets.read", {"ticket_id": "T-100"})))

    step("4. The agent reads a poisoned ticket and follows the hidden instruction")
    print(outcome(lab.call(token, "tickets.read", {"ticket_id": "T-200"})))
    print("agent obeys injected text and calls admin.export_users ...")
    print(outcome(lab.call(token, "admin.export_users")))

    step("5. An attacker steals the token but not the agent's DPoP key")
    from agent_broker.client import AgentClient
    from idkit import KeyPair

    thief = AgentClient("agent:helpdesk-bot", KeyPair.generate(), "", lab.broker)
    print(outcome(thief.call_tool(MCP, token, "tickets.read", {"ticket_id": "T-100"}, gateway=lab.gateway)))

    step("6. Frank (finance) asks the agent for a $40 refund")
    frank = lab.token("frank", ["finance"], ["payments.refund"])
    print(
        "without approval:", outcome(lab.call(frank, "payments.refund", {"ticket_id": "T-200", "amount": 40}))
    )
    approval = lab.approve("frank", "payments.refund", approver="user:finance-manager")
    print(
        "with approval:   ",
        outcome(lab.call(frank, "payments.refund", {"ticket_id": "T-200", "amount": 40}, approval)),
    )

    step("7. Alice leaves the company; the IdP deactivates her over SCIM")
    lab.deactivate(alice_scim_id)
    print("agent retries with Alice's still-unexpired token:")
    print(outcome(lab.call(token, "tickets.read", {"ticket_id": "T-100"})))

    step("Audit trail")
    for event in lab.audit.events:
        fields = {k: v for k, v in event.items() if k not in ("ts", "jti", "approval_id")}
        print(" ", json.dumps(fields))


if __name__ == "__main__":
    main()
