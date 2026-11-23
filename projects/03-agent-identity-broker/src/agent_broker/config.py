from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from idkit import JWKS, AuditLog, KeyPair, ReplayCache


@dataclass
class AgentRegistration:
    """An AI agent the broker knows about.

    The agent authenticates either with a key it holds (`jwk`) or, when it runs as a
    SPIFFE workload, with a JWT-SVID for `spiffe_id`. Set `jwk=None` for SVID-only agents.
    """

    agent_id: str
    jwk: dict | None
    owner: str
    allowed_scopes: set[str]
    allowed_resources: set[str]
    spiffe_id: str | None = None


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
    # SPIFFE workload identity: the trust domain and a callable returning its current
    # JWT-SVID keys (e.g. fetched from the SPIRE OIDC discovery provider or Workload API).
    spiffe_trust_domain: str | None = None
    spiffe_bundle: Callable[[], JWKS] | None = None
    audit: AuditLog = field(default_factory=AuditLog)


@dataclass
class BrokerState:
    revoked_users: set[str] = field(default_factory=set)
    disabled_agents: set[str] = field(default_factory=set)
    actor_replay: ReplayCache = field(default_factory=ReplayCache)
    dpop_replay: ReplayCache = field(default_factory=ReplayCache)
