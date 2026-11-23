"""Client side used by an AI agent: get a delegated token, then call MCP tools with it."""

from __future__ import annotations

import itertools
from collections.abc import Callable

import httpx

from idkit import KeyPair, make_proof, new_claims, sign

from .app import GRANT_TOKEN_EXCHANGE, TT_ID_TOKEN, TT_JWT


class BrokerError(Exception):
    def __init__(self, status: int, body: dict) -> None:
        super().__init__(f"{status} {body.get('error')}: {body.get('error_description')}")
        self.status = status
        self.body = body


class AgentClient:
    def __init__(
        self,
        agent_id: str,
        key: KeyPair | None,
        broker_issuer: str,
        http: httpx.Client,
        dpop_key: KeyPair | None = None,
        svid_source: Callable[[str], str] | None = None,
    ) -> None:
        """Pass `key` to authenticate with a registered key, or `svid_source` (a function
        returning a JWT-SVID for a given audience, e.g. from the SPIFFE Workload API)."""
        if key is None and svid_source is None:
            raise ValueError("need a key or an SVID source")
        self.agent_id = agent_id
        self.key = key
        self.svid_source = svid_source
        self.dpop_key = dpop_key or KeyPair.generate()
        self.broker_issuer = broker_issuer
        self.http = http
        self._ids = itertools.count(1)

    @property
    def token_endpoint(self) -> str:
        return f"{self.broker_issuer}/token"

    def actor_assertion(self, ttl: int = 60) -> str:
        if self.svid_source is not None:
            return self.svid_source(self.token_endpoint)
        claims = new_claims(self.agent_id, self.agent_id, self.token_endpoint, ttl)
        return sign(claims, self.key)

    def exchange(self, subject_token: str, resource: str, scopes: list[str]) -> dict:
        response = self.http.post(
            self.token_endpoint,
            data={
                "grant_type": GRANT_TOKEN_EXCHANGE,
                "subject_token": subject_token,
                "subject_token_type": TT_ID_TOKEN,
                "actor_token": self.actor_assertion(),
                "actor_token_type": TT_JWT,
                "resource": resource,
                "scope": " ".join(scopes),
            },
            headers={"DPoP": make_proof(self.dpop_key, "POST", self.token_endpoint)},
        )
        body = response.json()
        if response.status_code != 200:
            raise BrokerError(response.status_code, body)
        return body

    def rpc(
        self,
        mcp_url: str,
        access_token: str,
        method: str,
        params: dict | None = None,
        gateway: httpx.Client | None = None,
    ) -> httpx.Response:
        payload = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        headers = {
            "Authorization": f"DPoP {access_token}",
            "DPoP": make_proof(self.dpop_key, "POST", mcp_url, access_token=access_token),
        }
        return (gateway or self.http).post(mcp_url, json=payload, headers=headers)

    def call_tool(
        self,
        mcp_url: str,
        access_token: str,
        name: str,
        arguments: dict | None = None,
        approval_id: str | None = None,
        gateway: httpx.Client | None = None,
    ) -> httpx.Response:
        params: dict = {"name": name, "arguments": arguments or {}}
        if approval_id:
            params["_meta"] = {"approval_id": approval_id}
        return self.rpc(mcp_url, access_token, "tools/call", params, gateway)
