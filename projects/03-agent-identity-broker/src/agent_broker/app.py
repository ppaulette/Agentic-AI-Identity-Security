"""Agent Identity Broker.

Issues short-lived, audience-restricted, DPoP-bound access tokens that let an AI
agent act on behalf of a user (OAuth 2.0 Token Exchange, RFC 8693). The granted
scope is the intersection of what was requested, what the agent is registered
for, and what the user's roles allow.
"""

from __future__ import annotations

import hmac

import jwt
from fastapi import FastAPI, Form, Header, Request
from fastapi.responses import JSONResponse

from idkit import JWKS, TokenError, new_claims, sign, verify, verify_proof

from .config import BrokerConfig, BrokerState

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TT_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
TT_JWT = "urn:ietf:params:oauth:token-type:jwt"
TT_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


def oauth_error(status: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _secret_matches(given: str | None, expected: str) -> bool:
    return given is not None and hmac.compare_digest(given.encode(), expected.encode())


def create_app(config: BrokerConfig, state: BrokerState | None = None) -> FastAPI:
    state = state or BrokerState()
    audit = config.audit
    token_endpoint = f"{config.issuer}/token"
    app = FastAPI(title="Agent Identity Broker", version="0.1.0")
    app.state.broker = state
    app.state.signing_key = config.signing_key

    @app.get("/.well-known/oauth-authorization-server")
    def metadata() -> dict:
        # RFC 8414
        return {
            "issuer": config.issuer,
            "token_endpoint": token_endpoint,
            "introspection_endpoint": f"{config.issuer}/introspect",
            "jwks_uri": f"{config.issuer}/jwks.json",
            "grant_types_supported": [GRANT_TOKEN_EXCHANGE],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "dpop_signing_alg_values_supported": ["ES256"],
        }

    @app.get("/jwks.json")
    def jwks() -> dict:
        return JWKS([config.signing_key.jwk]).as_dict()

    @app.post("/token")
    def token(
        grant_type: str = Form(...),
        subject_token: str = Form(...),
        subject_token_type: str = Form(...),
        actor_token: str = Form(...),
        actor_token_type: str = Form(...),
        resource: str = Form(...),
        scope: str = Form(""),
        dpop: str | None = Header(default=None, alias="DPoP"),
    ):
        if grant_type != GRANT_TOKEN_EXCHANGE:
            return oauth_error(400, "unsupported_grant_type", "only token exchange is supported")

        # 1. Proof of possession: the issued token will be bound to this key.
        if not dpop:
            return oauth_error(400, "invalid_dpop_proof", "DPoP proof required")
        try:
            jkt = verify_proof(dpop, htm="POST", htu=token_endpoint, replay_cache=state.dpop_replay)
        except TokenError as exc:
            return oauth_error(400, "invalid_dpop_proof", str(exc))

        # 2. Who is the agent? (RFC 7523-style signed assertion as the actor token)
        if actor_token_type != TT_JWT:
            return oauth_error(400, "invalid_request", "actor_token_type must be a JWT")
        try:
            agent_id = jwt.decode(actor_token, options={"verify_signature": False}).get("iss", "")
        except jwt.PyJWTError:
            return oauth_error(401, "invalid_client", "malformed actor token")
        agent = config.agents.get(agent_id)
        if agent is None:
            audit.record("token.denied", agent=agent_id, reason="unknown agent")
            return oauth_error(401, "invalid_client", "unknown agent")
        try:
            actor = verify(actor_token, JWKS([agent.jwk]), issuer=agent_id, audience=token_endpoint)
        except TokenError as exc:
            audit.record("token.denied", agent=agent_id, reason=str(exc))
            return oauth_error(401, "invalid_client", f"agent authentication failed: {exc}")
        if actor["sub"] != agent_id:
            return oauth_error(401, "invalid_client", "actor sub must equal iss")
        if not state.actor_replay.check_and_store(actor["jti"]):
            audit.record("token.denied", agent=agent_id, reason="actor assertion replayed")
            return oauth_error(401, "invalid_client", "actor assertion replayed")
        if agent_id in state.disabled_agents:
            audit.record("token.denied", agent=agent_id, reason="agent disabled")
            return oauth_error(401, "invalid_client", "agent disabled")

        # 3. Who is the user the agent acts for?
        if subject_token_type not in (TT_ID_TOKEN, TT_JWT):
            return oauth_error(400, "invalid_request", "unsupported subject_token_type")
        try:
            user = verify(subject_token, config.idp_jwks, issuer=config.idp_issuer, audience=config.issuer)
        except TokenError as exc:
            audit.record("token.denied", agent=agent_id, reason=f"subject token: {exc}")
            return oauth_error(400, "invalid_grant", f"subject token rejected: {exc}")
        if user["sub"] in state.revoked_users:
            audit.record("token.denied", agent=agent_id, user=user["sub"], reason="user revoked")
            return oauth_error(400, "invalid_grant", "user is deprovisioned")

        # 4. Where will the token be used? (RFC 8707)
        if resource not in agent.allowed_resources:
            audit.record(
                "token.denied",
                agent=agent_id,
                user=user["sub"],
                resource=resource,
                reason="resource not allowed for agent",
            )
            return oauth_error(400, "invalid_target", "agent is not registered for this resource")

        # 5. Down-scope: requested ∩ agent registration ∩ user's roles
        requested = set(scope.split())
        user_scopes = set().union(*(config.role_scopes.get(r, set()) for r in user.get("roles", [])))
        granted = requested & agent.allowed_scopes & user_scopes
        if not granted:
            audit.record(
                "token.denied",
                agent=agent_id,
                user=user["sub"],
                requested=sorted(requested),
                reason="no grantable scope",
            )
            return oauth_error(400, "invalid_scope", "none of the requested scopes can be granted")

        claims = new_claims(
            config.issuer,
            user["sub"],
            resource,
            config.token_ttl,
            client_id=agent_id,
            act={"sub": agent_id},
            scope=" ".join(sorted(granted)),
            cnf={"jkt": jkt},
        )
        access_token = sign(claims, config.signing_key, typ="at+jwt")
        audit.record(
            "token.issued",
            jti=claims["jti"],
            user=user["sub"],
            agent=agent_id,
            resource=resource,
            granted=sorted(granted),
            dropped=sorted(requested - granted),
        )
        return JSONResponse(
            {
                "access_token": access_token,
                "issued_token_type": TT_ACCESS_TOKEN,
                "token_type": "DPoP",
                "expires_in": config.token_ttl,
                "scope": claims["scope"],
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/introspect")
    def introspect(request: Request, token: str = Form(...)):
        # RFC 7662. Each resource server may only introspect tokens issued for itself.
        auth = request.headers.get("authorization", "")
        caller = next(
            (
                rs
                for rs, secret in config.resource_servers.items()
                if _secret_matches(auth.removeprefix("Bearer "), secret)
            ),
            None,
        )
        if caller is None:
            return oauth_error(401, "invalid_client", "resource server authentication failed")
        try:
            claims = verify(
                token, JWKS([config.signing_key.jwk]), issuer=config.issuer, audience=caller, typ="at+jwt"
            )
        except TokenError:
            return {"active": False}
        agent_id = claims.get("act", {}).get("sub")
        if claims["sub"] in state.revoked_users or agent_id in state.disabled_agents:
            return {"active": False}
        return {"active": True, "token_type": "DPoP", **claims}

    def _event_auth(request: Request) -> bool:
        return _secret_matches(request.headers.get("x-event-secret"), config.events_secret)

    @app.post("/events/user-deprovisioned")
    async def user_deprovisioned(request: Request):
        if not _event_auth(request):
            return oauth_error(401, "invalid_client", "bad event secret")
        user = (await request.json())["user"]
        state.revoked_users.add(user)
        audit.record("user.revoked", user=user)
        return {"revoked": user}

    @app.post("/events/agent-disabled")
    async def agent_disabled(request: Request):
        if not _event_auth(request):
            return oauth_error(401, "invalid_client", "bad event secret")
        agent_id = (await request.json())["agent"]
        state.disabled_agents.add(agent_id)
        audit.record("agent.disabled", agent=agent_id)
        return {"disabled": agent_id}

    return app
