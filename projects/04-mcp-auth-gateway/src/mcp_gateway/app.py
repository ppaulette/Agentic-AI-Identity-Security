"""An MCP server (JSON-RPC over HTTP) protected as an OAuth resource server.

Every request goes through five checks before a tool runs:

1. Access token signature, issuer, audience, expiry and type (RFC 9068 at+jwt)
2. DPoP proof bound to that token (RFC 9449): right key, method, URL, fresh, unused
3. Introspection with the broker (RFC 7662) so revocation takes effect immediately
4. An AuthZEN decision from the PDP for this agent, user and tool
5. Human approval, bound to the user and tool, for high-risk calls

It implements the subset of MCP needed here (initialize, tools/list, tools/call),
and advertises itself with OAuth Protected Resource Metadata (RFC 9728) as the MCP
authorization spec requires.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from idkit import JWKS, AuditLog, ReplayCache, TokenError, verify, verify_proof

from .tools import TOOL_SCOPES, TOOLS, run_tool

PROTOCOL_VERSION = "2025-06-18"


@dataclass
class GatewayConfig:
    resource: str  # this server's MCP endpoint URL; also the token audience
    broker_issuer: str
    introspection_secret: str
    pdp_url: str
    broker: httpx.Client
    pdp: httpx.Client
    audit: AuditLog = field(default_factory=AuditLog)
    approvers_token: str = field(default_factory=lambda: secrets.token_urlsafe(16))


class AuthFailure(Exception):
    def __init__(self, status: int, error: str, description: str) -> None:
        self.status, self.error, self.description = status, error, description


def create_app(config: GatewayConfig) -> FastAPI:
    app = FastAPI(title="MCP auth gateway", version="0.1.0")
    origin = config.resource.rsplit("/", 1)[0]
    metadata_url = f"{origin}/.well-known/oauth-protected-resource"
    dpop_replay = ReplayCache()
    approvals: dict[str, dict] = {}
    comments: list = []
    jwks_cache: dict[str, JWKS] = {}
    app.state.comments = comments

    def broker_jwks(refresh: bool = False) -> JWKS:
        if refresh or "keys" not in jwks_cache:
            body = config.broker.get(f"{config.broker_issuer}/jwks.json").json()
            jwks_cache["keys"] = JWKS(body["keys"])
        return jwks_cache["keys"]

    def challenge(exc: AuthFailure) -> JSONResponse:
        header = (
            f'DPoP resource_metadata="{metadata_url}", algs="ES256", '
            f'error="{exc.error}", error_description="{exc.description}"'
        )
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers={"WWW-Authenticate": header},
        )

    def authenticate(request: Request) -> dict:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "dpop" or not token:
            raise AuthFailure(401, "invalid_token", "DPoP-bound access token required")
        try:
            claims = verify(
                token, broker_jwks(), issuer=config.broker_issuer, audience=config.resource, typ="at+jwt"
            )
        except TokenError as exc:
            if "unknown signing key" in str(exc):  # broker may have rotated keys
                try:
                    claims = verify(
                        token,
                        broker_jwks(refresh=True),
                        issuer=config.broker_issuer,
                        audience=config.resource,
                        typ="at+jwt",
                    )
                except TokenError as exc2:
                    raise AuthFailure(401, "invalid_token", str(exc2)) from exc2
            else:
                raise AuthFailure(401, "invalid_token", str(exc)) from exc
        jkt = (claims.get("cnf") or {}).get("jkt")
        if not jkt:
            raise AuthFailure(401, "invalid_token", "token is not DPoP-bound")
        try:
            verify_proof(
                request.headers.get("dpop", ""),
                htm="POST",
                htu=config.resource,
                replay_cache=dpop_replay,
                access_token=token,
                expected_jkt=jkt,
            )
        except TokenError as exc:
            raise AuthFailure(401, "invalid_dpop_proof", str(exc)) from exc
        status = config.broker.post(
            f"{config.broker_issuer}/introspect",
            data={"token": token},
            headers={"Authorization": f"Bearer {config.introspection_secret}"},
        ).json()
        if not status.get("active"):
            raise AuthFailure(401, "invalid_token", "token is no longer active")
        return claims

    def rpc_result(req_id, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def rpc_error(req_id, code: int, message: str, data: dict | None = None, status: int = 200):
        err = {"code": code, "message": message, **({"data": data} if data else {})}
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": err}, status_code=status)

    @app.get("/.well-known/oauth-protected-resource")
    def protected_resource_metadata() -> dict:
        return {
            "resource": config.resource,
            "authorization_servers": [config.broker_issuer],
            "scopes_supported": sorted(set(TOOL_SCOPES.values())),
            "bearer_methods_supported": ["header"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "dpop_bound_access_tokens_required": True,
        }

    @app.post("/approvals")
    async def create_approval(request: Request):
        """A human approver grants one high-risk call for one user and tool."""
        if not secrets.compare_digest(request.headers.get("x-approver-token", ""), config.approvers_token):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        approval_id = secrets.token_urlsafe(12)
        approvals[approval_id] = {"user": body["user"], "tool": body["tool"], "approver": body["approver"]}
        config.audit.record("approval.granted", approval_id=approval_id, **approvals[approval_id])
        return {"approval_id": approval_id}

    @app.post("/mcp")
    async def mcp(request: Request):
        try:
            claims = authenticate(request)
        except AuthFailure as exc:
            config.audit.record("mcp.auth_failed", error=exc.error, reason=exc.description)
            return challenge(exc)

        body = await request.json()
        req_id, method, params = body.get("id"), body.get("method"), body.get("params") or {}
        user, agent = claims["sub"], claims["act"]["sub"]
        scopes = set(claims.get("scope", "").split())

        if method == "initialize":
            return rpc_result(
                req_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "helpdesk-mcp", "version": "0.1.0"},
                },
            )
        if method == "tools/list":
            visible = [{"name": n, **t} for n, t in TOOLS.items() if TOOL_SCOPES[n] in scopes]
            return rpc_result(req_id, {"tools": visible})
        if method != "tools/call":
            return rpc_error(req_id, -32601, f"method {method!r} not found")

        name, args = params.get("name", ""), params.get("arguments") or {}
        approval_id = (params.get("_meta") or {}).get("approval_id")
        approval = approvals.get(approval_id) if approval_id else None
        approved = bool(approval and approval["user"] == user and approval["tool"] == name)

        decision = config.pdp.post(
            config.pdp_url,
            json={
                "subject": {
                    "type": "agent",
                    "id": agent,
                    "properties": {"acting_for": user, "scopes": sorted(scopes)},
                },
                "action": {"name": "tools/call"},
                "resource": {"type": "tool", "id": name},
                "context": {"human_approval": approved, "arguments": args, "token_jti": claims["jti"]},
            },
        ).json()
        reason = decision.get("context", {}).get("reason", "")
        config.audit.record(
            "mcp.tool_call",
            user=user,
            agent=agent,
            tool=name,
            decision="allow" if decision.get("decision") else "deny",
            reason=reason,
        )
        if not decision.get("decision"):
            if decision.get("context", {}).get("rule") == "scope":
                exc = AuthFailure(403, "insufficient_scope", reason)
                response = challenge(exc)
                response.headers["WWW-Authenticate"] += f', scope="{TOOL_SCOPES.get(name, "")}"'
                return response
            return rpc_error(req_id, -32001, "Forbidden by policy", {"reason": reason}, status=403)

        if approval_id and approved:
            approvals.pop(approval_id)  # single use
        text = run_tool(name, args, comments)
        return rpc_result(req_id, {"content": [{"type": "text", "text": text}], "isError": False})

    return app
