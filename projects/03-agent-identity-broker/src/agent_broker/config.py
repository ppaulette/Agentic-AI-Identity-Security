from __future__ import annotations

from dataclasses import dataclass, field

from idkit import JWKS, AuditLog, KeyPair, ReplayCache


@dataclass
class AgentRegistration:
    """An AI agent the broker knows about. The agent proves possession of `jwk`'s private key."""

    agent_id: str
    jwk: dict
    owner: str
    allowed_scopes: set[str]
    allowed_resources: set[str]


@dataclass
class BrokerConfig:
    issuer: str
    idp_issuer: str
    idp_jwks: JWKS
    role_scopes: dict[str, set[str]]
    agents: dict[str, AgentRegistration]
    # resource server URL -> shared secret it uses to call /introspect
    resource_servers: dict[str, str]
    events_secret: str
    signing_key: KeyPair = field(default_factory=lambda: KeyPair.generate(kid="broker-1"))
    token_ttl: int = 300
    audit: AuditLog = field(default_factory=AuditLog)


@dataclass
class BrokerState:
    revoked_users: set[str] = field(default_factory=set)
    disabled_agents: set[str] = field(default_factory=set)
    actor_replay: ReplayCache = field(default_factory=ReplayCache)
    dpop_replay: ReplayCache = field(default_factory=ReplayCache)
