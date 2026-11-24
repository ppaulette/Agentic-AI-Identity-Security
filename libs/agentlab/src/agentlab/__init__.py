"""One-process lab: IdP → SCIM → broker → MCP gateway → PDP, all talking over in-memory HTTP.

Each service gets its own hostname so URLs, audiences and DPoP `htu` values look the
same as they would in a real deployment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi.testclient import TestClient

from agent_broker.app import create_app as create_broker
from agent_broker.client import AgentClient
from agent_broker.config import AgentRegistration, BrokerConfig
from authzen_pdp.app import create_app as create_pdp
from idkit import JWKS, AuditLog, KeyPair, MockIdP, MockSpire
from mcp_gateway.app import GatewayConfig
from mcp_gateway.app import create_app as create_gateway
from scim_server.app import USER_SCHEMA
from scim_server.app import create_app as create_scim

BROKER = "https://broker.example.test"
PDP = "https://pdp.example.test"
SCIM = "https://scim.example.test"
GATEWAY_ORIGIN = "https://mcp.tickets.example"
MCP = f"{GATEWAY_ORIGIN}/mcp"
AGENT_ID = "agent:helpdesk-bot"
SVID_AGENT_ID = "agent:triage-bot"  # runs as a SPIFFE workload, holds no registered key
TRUST_DOMAIN = "corp.example"
SVID_PATH = "/ns/agents/sa/triage-bot"

ROLE_SCOPES = {
    "support": {"tickets.read", "tickets.write"},
    "finance": {"payments.refund", "tickets.read"},
    "admin": {"admin.export"},
}


@dataclass
class Lab:
    idp: MockIdP
    audit: AuditLog
    broker: TestClient
    pdp: TestClient
    scim: TestClient
    gateway: TestClient
    gateway_config: GatewayConfig
    agent: AgentClient
    agent_key: KeyPair
    spire: MockSpire
    svid_agent: AgentClient
    scim_token: str = "idp-provisioning-token"

    def id_token(self, user: str, roles: list[str]) -> str:
        return self.idp.id_token(f"user:{user}", BROKER, roles)

    def token(self, user: str, roles: list[str], scopes: list[str]) -> str:
        return self.agent.exchange(self.id_token(user, roles), MCP, scopes)["access_token"]

    def call(self, token: str, tool: str, args: dict | None = None, approval_id: str | None = None):
        return self.agent.call_tool(MCP, token, tool, args, approval_id, gateway=self.gateway)

    def approve(self, user: str, tool: str, approver: str = "user:manager") -> str:
        r = self.gateway.post(
            "/approvals",
            json={"user": f"user:{user}", "tool": tool, "approver": approver},
            headers={"X-Approver-Token": self.gateway_config.approvers_token},
        )
        return r.json()["approval_id"]

    def provision(self, user: str) -> str:
        r = self.scim.post(
            "/scim/v2/Users",
            headers={"Authorization": f"Bearer {self.scim_token}"},
            json={"schemas": [USER_SCHEMA], "userName": user, "active": True},
        )
        return r.json()["id"]

    def deactivate(self, scim_id: str) -> None:
        self.scim.patch(
            f"/scim/v2/Users/{scim_id}",
            headers={"Authorization": f"Bearer {self.scim_token}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "value": {"active": False}}],
            },
        )


def build_lab(
    spiffe_bundle: Callable[[], JWKS] | None = None,
    svid_source: Callable[[str], str] | None = None,
) -> Lab:
    """Build the lab. By default SPIFFE is simulated with MockSpire; pass `spiffe_bundle` and
    `svid_source` to use a real SPIRE deployment instead (see projects/06-workload-identity).
    """
    audit = AuditLog()
    idp = MockIdP()
    agent_key = KeyPair.generate(kid=AGENT_ID)
    spire = MockSpire(TRUST_DOMAIN)
    rs_secret, events_secret = "rs-introspection-secret", "broker-events-secret"

    broker_config = BrokerConfig(
        issuer=BROKER,
        idp_issuer=idp.issuer,
        idp_jwks=idp.jwks,
        role_scopes=ROLE_SCOPES,
        agents={
            AGENT_ID: AgentRegistration(
                AGENT_ID,
                agent_key.jwk,
                owner="team:support",
                allowed_scopes={"tickets.read", "tickets.write", "payments.refund"},
                allowed_resources={MCP},
            ),
            SVID_AGENT_ID: AgentRegistration(
                SVID_AGENT_ID,
                None,
                owner="team:support",
                allowed_scopes={"tickets.read"},
                allowed_resources={MCP},
                spiffe_id=f"spiffe://{TRUST_DOMAIN}{SVID_PATH}",
            ),
        },
        resource_servers={MCP: rs_secret},
        events_secret=events_secret,
        spiffe_trust_domain=TRUST_DOMAIN,
        spiffe_bundle=spiffe_bundle or spire.jwks,
        audit=audit,
    )
    broker = TestClient(create_broker(broker_config), base_url=BROKER)
    pdp = TestClient(create_pdp(issuer=PDP), base_url=PDP)
    gateway_config = GatewayConfig(
        resource=MCP,
        broker_issuer=BROKER,
        introspection_secret=rs_secret,
        pdp_url=f"{PDP}/access/v1/evaluation",
        broker=broker,
        pdp=pdp,
        audit=audit,
    )
    gateway = TestClient(create_gateway(gateway_config), base_url=GATEWAY_ORIGIN)
    scim = TestClient(
        create_scim(
            "idp-provisioning-token",
            broker=broker,
            broker_url=BROKER,
            events_secret=events_secret,
            audit=audit,
            base_url=SCIM,
        ),
        base_url=SCIM,
    )
    agent = AgentClient(AGENT_ID, agent_key, BROKER, broker)
    svid_source = svid_source or spire.source(SVID_PATH)
    svid_agent = AgentClient(SVID_AGENT_ID, None, BROKER, broker, svid_source=svid_source)
    return Lab(idp, audit, broker, pdp, scim, gateway, gateway_config, agent, agent_key, spire, svid_agent)
