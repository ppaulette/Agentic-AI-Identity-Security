"""Attacks an adversary would try against an agent identity stack.

Each attack runs against a fresh lab and reports whether it was blocked, which
control stopped it, and the evidence (status code and error) the system returned.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import jwt

from agent_broker.client import AgentClient, BrokerError
from agentlab import AGENT_ID, BROKER, MCP, Lab
from idkit import KeyPair, make_proof, new_claims, sign


@dataclass
class Outcome:
    blocked: bool
    evidence: str


@dataclass
class Attack:
    id: str
    name: str
    threat: str  # OWASP LLM / agentic threat or classic OAuth threat it maps to
    expected_control: str
    run: Callable[[Lab], Outcome]


def _evidence(response) -> str:
    body = response.json()
    detail = (
        body.get("error_description")
        or body.get("error", {}).get("data", {}).get("reason")
        or body.get("error", {})
    )
    return f"HTTP {response.status_code}: {detail}"


def _gateway_outcome(response) -> Outcome:
    return Outcome(response.status_code in (401, 403), _evidence(response))


# --- token theft and replay -------------------------------------------------


def stolen_token_without_key(lab: Lab) -> Outcome:
    token = lab.token("alice", ["support"], ["tickets.read"])
    attacker = AgentClient(AGENT_ID, KeyPair.generate(), BROKER, lab.broker)  # has token, not DPoP key
    return _gateway_outcome(
        attacker.call_tool(MCP, token, "tickets.read", {"ticket_id": "T-100"}, gateway=lab.gateway)
    )


def stolen_token_as_bearer(lab: Lab) -> Outcome:
    token = lab.token("alice", ["support"], ["tickets.read"])
    r = lab.gateway.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    return _gateway_outcome(r)


def replayed_dpop_proof(lab: Lab) -> Outcome:
    token = lab.token("alice", ["support"], ["tickets.read"])
    headers = {
        "Authorization": f"DPoP {token}",
        "DPoP": make_proof(lab.agent.dpop_key, "POST", MCP, access_token=token),
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    lab.gateway.post("/mcp", json=body, headers=headers)  # legitimate request
    return _gateway_outcome(lab.gateway.post("/mcp", json=body, headers=headers))  # captured + replayed


def _genuine_token(lab: Lab, **overrides) -> str:
    """Mint a token with the broker's real key, as if captured from another context.

    The lab exposes the key only so these tests can model a stolen-but-genuine token.
    """
    claims = jwt.decode(
        lab.token("alice", ["support"], ["tickets.read"]), options={"verify_signature": False}
    )
    claims.update(overrides)
    return sign(claims, lab.broker.app.state.signing_key, typ="at+jwt")


def token_for_other_resource(lab: Lab) -> Outcome:
    token = _genuine_token(lab, aud="https://payroll.example/api")
    return _gateway_outcome(lab.call(token, "tickets.read", {"ticket_id": "T-100"}))


def expired_token(lab: Lab) -> Outcome:
    token = _genuine_token(lab, exp=int(time.time()) - 60)
    return _gateway_outcome(lab.call(token, "tickets.read", {"ticket_id": "T-100"}))


def alg_none_token(lab: Lab) -> Outcome:
    claims = new_claims(
        BROKER,
        "user:alice",
        MCP,
        300,
        act={"sub": AGENT_ID},
        scope="tickets.read admin.export",
        cnf={"jkt": lab.agent.dpop_key.thumbprint},
    )
    unsigned = jwt.encode(claims, None, algorithm="none", headers={"typ": "at+jwt", "kid": "broker-1"})
    return _gateway_outcome(lab.call(unsigned, "admin.export_users"))


def forged_act_claim(lab: Lab) -> Outcome:
    claims = jwt.decode(
        lab.token("alice", ["support"], ["tickets.read"]), options={"verify_signature": False}
    )
    claims["act"] = {"sub": "agent:trusted-admin-bot"}
    claims["scope"] = "tickets.read admin.export"
    forged = sign(claims, KeyPair.generate(kid="broker-1"), typ="at+jwt")
    return _gateway_outcome(lab.call(forged, "admin.export_users"))


# --- agent impersonation and privilege expansion ----------------------------


def agent_impersonation(lab: Lab) -> Outcome:
    impostor = AgentClient(AGENT_ID, KeyPair.generate(kid=AGENT_ID), BROKER, lab.broker)
    try:
        impostor.exchange(lab.id_token("alice", ["support"]), MCP, ["tickets.read"])
    except BrokerError as exc:
        return Outcome(True, f"HTTP {exc.status}: {exc.body['error_description']}")
    return Outcome(False, "impostor received a token")


def actor_assertion_replay(lab: Lab) -> Outcome:
    assertion = lab.agent.actor_assertion()
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": lab.id_token("alice", ["support"]),
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "actor_token": assertion,
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "resource": MCP,
        "scope": "tickets.read",
    }
    proof = lambda: make_proof(lab.agent.dpop_key, "POST", f"{BROKER}/token")  # noqa: E731
    lab.broker.post("/token", data=form, headers={"DPoP": proof()})
    r = lab.broker.post("/token", data=form, headers={"DPoP": proof()})
    return Outcome(r.status_code == 401, _evidence(r))


def scope_escalation(lab: Lab) -> Outcome:
    # A support user's agent asks for refund and admin scopes it should never get.
    result = lab.agent.exchange(
        lab.id_token("alice", ["support"]), MCP, ["tickets.read", "payments.refund", "admin.export"]
    )
    granted = set(result["scope"].split())
    return Outcome(granted == {"tickets.read"}, f"granted only: {result['scope']}")


def confused_deputy_other_resource(lab: Lab) -> Outcome:
    try:
        lab.agent.exchange(
            lab.id_token("alice", ["support"]), "https://payroll.example/api", ["tickets.read"]
        )
    except BrokerError as exc:
        return Outcome(True, f"HTTP {exc.status}: {exc.body['error_description']}")
    return Outcome(False, "token issued for an unregistered resource")


def rogue_idp_subject_token(lab: Lab) -> Outcome:
    from idkit import MockIdP

    rogue = MockIdP(issuer=lab.idp.issuer)  # same issuer string, attacker's key
    try:
        lab.agent.exchange(rogue.id_token("user:ceo", BROKER, ["finance", "admin"]), MCP, ["payments.refund"])
    except BrokerError as exc:
        return Outcome(True, f"HTTP {exc.status}: {exc.body['error_description']}")
    return Outcome(False, "forged ID token accepted")


# --- prompt injection and tool misuse ---------------------------------------


def prompt_injection_tool_misuse(lab: Lab) -> Outcome:
    """A naive agent reads a poisoned ticket and obeys the hidden instruction."""
    token = lab.token("alice", ["support"], ["tickets.read", "tickets.write"])
    ticket = lab.call(token, "tickets.read", {"ticket_id": "T-200"}).json()["result"]["content"][0]["text"]
    assert "admin.export_users" in ticket  # the injected instruction is really there
    return _gateway_outcome(lab.call(token, "admin.export_users"))  # the agent "obeys"


def injected_refund_without_approval(lab: Lab) -> Outcome:
    token = lab.token("frank", ["finance"], ["payments.refund"])
    return _gateway_outcome(lab.call(token, "payments.refund", {"ticket_id": "T-200", "amount": 40}))


def approval_reuse_for_bigger_amount(lab: Lab) -> Outcome:
    token = lab.token("frank", ["finance"], ["payments.refund"])
    approval = lab.approve("frank", "payments.refund")
    lab.call(token, "payments.refund", {"ticket_id": "T-200", "amount": 40}, approval)
    return _gateway_outcome(
        lab.call(token, "payments.refund", {"ticket_id": "T-200", "amount": 4000}, approval)
    )


def refund_over_limit_with_approval(lab: Lab) -> Outcome:
    token = lab.token("frank", ["finance"], ["payments.refund"])
    approval = lab.approve("frank", "payments.refund")
    return _gateway_outcome(
        lab.call(token, "payments.refund", {"ticket_id": "T-200", "amount": 4000}, approval)
    )


# --- lifecycle ---------------------------------------------------------------


def deprovisioned_user_live_token(lab: Lab) -> Outcome:
    scim_id = lab.provision("alice")
    token = lab.token("alice", ["support"], ["tickets.read"])
    lab.deactivate(scim_id)  # IdP pushes SCIM PATCH active=false
    return _gateway_outcome(lab.call(token, "tickets.read", {"ticket_id": "T-100"}))


def compromised_agent_kill_switch(lab: Lab) -> Outcome:
    token = lab.token("alice", ["support"], ["tickets.read"])
    lab.broker.post(
        "/events/agent-disabled", json={"agent": AGENT_ID}, headers={"X-Event-Secret": "broker-events-secret"}
    )
    return _gateway_outcome(lab.call(token, "tickets.read", {"ticket_id": "T-100"}))


ATTACKS: list[Attack] = [
    Attack(
        "A01",
        "Stolen access token used without the DPoP key",
        "Token theft (OAuth)",
        "DPoP binding (cnf.jkt)",
        stolen_token_without_key,
    ),
    Attack(
        "A02",
        "Stolen DPoP token presented as a plain Bearer token",
        "Token theft (OAuth)",
        "DPoP scheme required",
        stolen_token_as_bearer,
    ),
    Attack(
        "A03",
        "Captured request replayed with the same DPoP proof",
        "Replay",
        "DPoP jti replay cache",
        replayed_dpop_proof,
    ),
    Attack(
        "A04",
        "Genuine token issued for another API presented here",
        "Token misuse across services",
        "Audience check (aud = this resource)",
        token_for_other_resource,
    ),
    Attack(
        "A05",
        "Captured token used after it expired",
        "Token replay",
        "Expiry check (5-minute tokens)",
        expired_token,
    ),
    Attack(
        "A06",
        "Unsigned token (alg=none) claiming admin scope",
        "Token forgery",
        "Algorithm pinned to ES256",
        alg_none_token,
    ),
    Attack(
        "A07",
        "Forged act claim to impersonate a more trusted agent",
        "Agent impersonation",
        "Signature check against broker JWKS",
        forged_act_claim,
    ),
    Attack(
        "A08",
        "Attacker presents a stolen agent ID with their own key",
        "Agent impersonation",
        "private_key_jwt client authentication",
        agent_impersonation,
    ),
    Attack(
        "A09",
        "Captured agent assertion replayed at the token endpoint",
        "Replay",
        "Actor assertion jti replay cache",
        actor_assertion_replay,
    ),
    Attack(
        "A10",
        "Agent requests scopes beyond the user's role",
        "Excessive agency / privilege expansion",
        "Scope intersection at the broker",
        scope_escalation,
    ),
    Attack(
        "A11",
        "Agent requests a token for a resource it is not registered for",
        "Confused deputy",
        "Resource indicator allow-list (RFC 8707)",
        confused_deputy_other_resource,
    ),
    Attack(
        "A12",
        "Forged ID token from a look-alike IdP",
        "Identity provider spoofing",
        "IdP JWKS pinning",
        rogue_idp_subject_token,
    ),
    Attack(
        "A13",
        "Prompt injection in a ticket makes the agent export all users",
        "Prompt injection → tool misuse (LLM01, LLM06)",
        "Agent-forbidden tool policy + scope",
        prompt_injection_tool_misuse,
    ),
    Attack(
        "A14",
        "Agent issues a refund with no human approval",
        "Excessive agency (LLM06)",
        "Step-up human approval",
        injected_refund_without_approval,
    ),
    Attack(
        "A15",
        "Approval for $40 reused for $4,000",
        "Unsafe delegation",
        "Single-use approvals",
        approval_reuse_for_bigger_amount,
    ),
    Attack(
        "A16",
        "Approved refund above the policy limit",
        "Excessive agency (LLM06)",
        "Amount limit in policy",
        refund_over_limit_with_approval,
    ),
    Attack(
        "A17",
        "User is deprovisioned while their agent holds a live token",
        "Orphaned access",
        "SCIM → broker revocation + introspection",
        deprovisioned_user_live_token,
    ),
    Attack(
        "A18",
        "Compromised agent keeps using its token",
        "Compromised agent",
        "Agent kill switch + introspection",
        compromised_agent_kill_switch,
    ),
]
