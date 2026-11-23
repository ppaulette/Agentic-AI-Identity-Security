import jwt
import pytest
from fastapi.testclient import TestClient

from agent_broker.app import create_app
from agent_broker.client import AgentClient, BrokerError
from agent_broker.config import AgentRegistration, BrokerConfig
from idkit import JWKS, KeyPair, MockIdP, MockSpire, make_proof

BROKER = "https://broker.example.test"
RS = "https://mcp.tickets.example/mcp"


@pytest.fixture
def env():
    idp = MockIdP()
    agent_key = KeyPair.generate(kid="agent:helpdesk-bot")
    config = BrokerConfig(
        issuer=BROKER,
        idp_issuer=idp.issuer,
        idp_jwks=idp.jwks,
        role_scopes={"support": {"tickets.read", "tickets.write"}, "finance": {"payments.refund"}},
        agents={
            "agent:helpdesk-bot": AgentRegistration(
                "agent:helpdesk-bot",
                agent_key.jwk,
                "team:support",
                {"tickets.read", "tickets.write", "payments.refund"},
                {RS},
            )
        },
        resource_servers={RS: "rs-secret", "https://other-rs.example/api": "other-secret"},
        events_secret="evt-secret",
    )
    http = TestClient(create_app(config), base_url=BROKER)
    agent = AgentClient("agent:helpdesk-bot", agent_key, BROKER, http)
    alice = idp.id_token("user:alice", BROKER, roles=["support"])
    return idp, config, http, agent, alice


def claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def test_delegated_token_shape(env):
    _, config, _, agent, alice = env
    result = agent.exchange(alice, RS, ["tickets.read"])
    assert result["token_type"] == "DPoP"
    c = claims(result["access_token"])
    assert c["sub"] == "user:alice"
    assert c["act"] == {"sub": "agent:helpdesk-bot"}
    assert c["aud"] == RS
    assert c["cnf"]["jkt"] == agent.dpop_key.thumbprint
    assert c["exp"] - c["iat"] == config.token_ttl
    assert jwt.get_unverified_header(result["access_token"])["typ"] == "at+jwt"


def test_scope_is_intersection_of_request_agent_and_user(env):
    _, config, _, agent, alice = env
    # alice is support: she cannot grant payments.refund even though the agent could use it
    result = agent.exchange(alice, RS, ["tickets.read", "payments.refund"])
    assert result["scope"] == "tickets.read"
    assert config.audit.find("token.issued")[-1]["dropped"] == ["payments.refund"]


def test_no_grantable_scope(env):
    *_, agent, alice = env
    with pytest.raises(BrokerError) as err:
        agent.exchange(alice, RS, ["payments.refund"])
    assert err.value.body["error"] == "invalid_scope"


def test_unregistered_resource(env):
    *_, agent, alice = env
    with pytest.raises(BrokerError) as err:
        agent.exchange(alice, "https://payroll.example/api", ["tickets.read"])
    assert err.value.body["error"] == "invalid_target"


def test_impostor_agent_rejected(env):
    _, _, http, _, alice = env
    impostor = AgentClient("agent:helpdesk-bot", KeyPair.generate(kid="agent:helpdesk-bot"), BROKER, http)
    with pytest.raises(BrokerError) as err:
        impostor.exchange(alice, RS, ["tickets.read"])
    assert err.value.body["error"] == "invalid_client"


def test_subject_token_from_untrusted_idp(env):
    *_, agent, _ = env
    rogue = MockIdP(issuer="https://idp.example.test")  # same issuer name, different key
    with pytest.raises(BrokerError) as err:
        agent.exchange(rogue.id_token("user:alice", BROKER, ["support"]), RS, ["tickets.read"])
    assert err.value.body["error"] == "invalid_grant"


def test_dpop_required_and_actor_replay_blocked(env):
    _, _, http, agent, alice = env
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": alice,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "actor_token": agent.actor_assertion(),
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "resource": RS,
        "scope": "tickets.read",
    }
    assert http.post("/token", data=form).json()["error"] == "invalid_dpop_proof"

    def proof():
        return {"DPoP": make_proof(agent.dpop_key, "POST", f"{BROKER}/token")}

    ok = http.post("/token", data=form, headers=proof())
    assert ok.status_code == 200
    replay = http.post("/token", data=form, headers=proof())
    assert replay.json()["error_description"] == "actor assertion replayed"


def test_introspection_and_revocation(env):
    _, config, http, agent, alice = env
    token = agent.exchange(alice, RS, ["tickets.read"])["access_token"]
    auth = {"Authorization": "Bearer rs-secret"}
    assert http.post("/introspect", data={"token": token}, headers=auth).json()["active"] is True
    assert http.post("/introspect", data={"token": token}).status_code == 401

    http.post(
        "/events/user-deprovisioned", json={"user": "user:alice"}, headers={"X-Event-Secret": "evt-secret"}
    )
    assert http.post("/introspect", data={"token": token}, headers=auth).json() == {"active": False}
    with pytest.raises(BrokerError):
        agent.exchange(alice, RS, ["tickets.read"])
    assert config.audit.find("user.revoked")


def test_agent_kill_switch(env):
    _, _, http, agent, alice = env
    assert http.post("/events/agent-disabled", json={"agent": "agent:helpdesk-bot"}).status_code == 401
    http.post(
        "/events/agent-disabled",
        json={"agent": "agent:helpdesk-bot"},
        headers={"X-Event-Secret": "evt-secret"},
    )
    with pytest.raises(BrokerError) as err:
        agent.exchange(alice, RS, ["tickets.read"])
    assert err.value.body["error_description"] == "agent disabled"


def test_cli_keygen_and_decode(tmp_path, capsys):
    from agent_broker.cli import main

    assert main(["keygen", "--agent-id", "agent:x", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "agent_x.pem").stat().st_mode & 0o777 == 0o600
    token = MockIdP().id_token("user:bob", BROKER, ["support"])
    assert main(["decode", token]) == 0
    assert "user:bob" in capsys.readouterr().out


def test_resource_server_cannot_introspect_tokens_for_others(env):
    *_, http, agent, alice = env
    token = agent.exchange(alice, RS, ["tickets.read"])["access_token"]
    other = {"Authorization": "Bearer other-secret"}
    assert http.post("/introspect", data={"token": token}, headers=other).json() == {"active": False}


# --- SPIFFE workload identity (JWT-SVID as the actor token) -----------------

SVID_PATH = "/ns/agents/sa/triage-bot"


@pytest.fixture
def spiffe_env():
    idp, spire = MockIdP(), MockSpire("corp.example")
    config = BrokerConfig(
        issuer=BROKER,
        idp_issuer=idp.issuer,
        idp_jwks=idp.jwks,
        role_scopes={"support": {"tickets.read"}},
        agents={
            "agent:triage-bot": AgentRegistration(
                "agent:triage-bot",
                None,
                "team:support",
                {"tickets.read"},
                {RS},
                spiffe_id=f"spiffe://corp.example{SVID_PATH}",
            )
        },
        resource_servers={RS: "rs-secret"},
        events_secret="evt-secret",
        spiffe_trust_domain="corp.example",
        spiffe_bundle=spire.jwks,
    )
    http = TestClient(create_app(config), base_url=BROKER)
    alice = idp.id_token("user:alice", BROKER, roles=["support"])
    return spire, config, http, alice


def test_agent_authenticates_with_jwt_svid(spiffe_env):
    spire, config, http, alice = spiffe_env
    agent = AgentClient("agent:triage-bot", None, BROKER, http, svid_source=spire.source(SVID_PATH))
    result = agent.exchange(alice, RS, ["tickets.read"])
    assert claims(result["access_token"])["act"] == {"sub": "agent:triage-bot"}
    issued = config.audit.find("token.issued")[-1]
    assert issued["agent_auth"] == "jwt-svid"
    assert issued["spiffe_id"] == f"spiffe://corp.example{SVID_PATH}"


@pytest.mark.parametrize(
    ("make_source", "message"),
    [
        (lambda spire: MockSpire("evil.example").source(SVID_PATH), "untrusted trust domain"),
        (lambda spire: MockSpire("corp.example").source(SVID_PATH), "SVID rejected"),
        (lambda spire: spire.source("/ns/agents/sa/unknown-bot"), "no agent registered"),
        (lambda spire: lambda aud: spire.jwt_svid(SVID_PATH, "https://other-service.example"), "audience"),
    ],
    ids=["foreign-trust-domain", "rogue-spire-key", "unregistered-workload", "wrong-audience"],
)
def test_bad_svids_rejected(spiffe_env, make_source, message):
    spire, _, http, alice = spiffe_env
    agent = AgentClient("agent:triage-bot", None, BROKER, http, svid_source=make_source(spire))
    with pytest.raises(BrokerError) as err:
        agent.exchange(alice, RS, ["tickets.read"])
    assert err.value.body["error"] == "invalid_client"
    assert message in err.value.body["error_description"]


def test_svid_login_disabled_when_not_configured(env):
    _, _, http, _, alice = env
    agent = AgentClient("agent:x", None, BROKER, http, svid_source=MockSpire().source("/x"))
    with pytest.raises(BrokerError) as err:
        agent.exchange(alice, RS, ["tickets.read"])
    assert "not enabled" in err.value.body["error_description"]


def test_spiffe_bundle_filters_to_jwt_keys():
    spire = MockSpire()
    bundle = spire.bundle()
    bundle["keys"].append({"kty": "EC", "use": "x509-svid", "x5c": ["..."]})  # no kid, X.509 key
    assert len(JWKS.from_spiffe_bundle(bundle).as_dict()["keys"]) == 1
