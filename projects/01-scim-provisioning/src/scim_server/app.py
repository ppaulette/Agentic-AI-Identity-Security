"""SCIM 2.0 (RFC 7643/7644) Users endpoint that closes the agent-access loop.

When the IdP deactivates or deletes a user, this server tells the Agent Identity
Broker, which immediately stops issuing and honoring tokens for agents acting on
that user's behalf.
"""

from __future__ import annotations

import hmac
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from idkit import AuditLog

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
MEDIA_TYPE = "application/scim+json"


def scim_error(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status, media_type=MEDIA_TYPE)


class SCIMException(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        self.status, self.detail, self.scim_type = status, detail, scim_type


def create_app(
    bearer_token: str,
    broker: httpx.Client | None = None,
    broker_url: str = "",
    events_secret: str = "",
    audit: AuditLog | None = None,
    base_url: str = "https://scim.example.test",
) -> FastAPI:
    app = FastAPI(title="SCIM provisioning", version="0.1.0")
    users: dict[str, dict] = {}
    audit = audit or AuditLog()
    app.state.users = users

    @app.exception_handler(SCIMException)
    def handle(_: Request, exc: SCIMException):
        return scim_error(exc.status, exc.detail, exc.scim_type)

    def authenticate(request: Request) -> None:
        given = request.headers.get("authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(given.encode(), bearer_token.encode()):
            raise SCIMException(401, "invalid bearer token")

    def subject(user: dict) -> str:
        return f"user:{user['userName']}"

    def notify_deprovisioned(user: dict, reason: str) -> None:
        audit.record("scim.deprovisioned", user=subject(user), reason=reason)
        if broker is None:
            return
        response = broker.post(
            f"{broker_url}/events/user-deprovisioned",
            json={"user": subject(user)},
            headers={"X-Event-Secret": events_secret},
        )
        response.raise_for_status()

    def stamp(user: dict, created: bool = False) -> dict:
        now = datetime.now(UTC).isoformat()
        meta = user.setdefault("meta", {"resourceType": "User"})
        if created:
            meta["created"] = now
        meta["lastModified"] = now
        meta["location"] = f"{base_url}/scim/v2/Users/{user['id']}"
        return user

    def get_or_404(user_id: str) -> dict:
        if user_id not in users:
            raise SCIMException(404, f"user {user_id} not found")
        return users[user_id]

    def respond(body: dict, status: int = 200) -> JSONResponse:
        return JSONResponse(body, status_code=status, media_type=MEDIA_TYPE)

    @app.get("/scim/v2/ServiceProviderConfig")
    def service_provider_config():
        return respond(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 200},
                "changePassword": {"supported": False},
                "sort": {"supported": False},
                "etag": {"supported": False},
                "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token"}],
            }
        )

    @app.post("/scim/v2/Users", dependencies=[Depends(authenticate)])
    async def create_user(request: Request):
        body = await request.json()
        if USER_SCHEMA not in body.get("schemas", []) or not body.get("userName"):
            raise SCIMException(400, "userName and the core User schema are required", "invalidValue")
        if any(u["userName"].lower() == body["userName"].lower() for u in users.values()):
            raise SCIMException(409, "userName already exists", "uniqueness")
        user = {**body, "id": str(uuid.uuid4()), "active": body.get("active", True)}
        users[user["id"]] = stamp(user, created=True)
        audit.record("scim.created", user=subject(user))
        return respond(user, 201)

    @app.get("/scim/v2/Users", dependencies=[Depends(authenticate)])
    def list_users(filter: str | None = None, startIndex: int = 1, count: int = 100):  # noqa: A002, N803
        found = list(users.values())
        if filter:
            match = re.fullmatch(r'\s*userName\s+eq\s+"([^"]+)"\s*', filter, flags=re.IGNORECASE)
            if not match:
                raise SCIMException(400, "only 'userName eq \"...\"' filters are supported", "invalidFilter")
            found = [u for u in found if u["userName"].lower() == match.group(1).lower()]
        page = found[startIndex - 1 : startIndex - 1 + count]
        return respond(
            {
                "schemas": [LIST_SCHEMA],
                "totalResults": len(found),
                "startIndex": startIndex,
                "itemsPerPage": len(page),
                "Resources": page,
            }
        )

    @app.get("/scim/v2/Users/{user_id}", dependencies=[Depends(authenticate)])
    def get_user(user_id: str):
        return respond(get_or_404(user_id))

    @app.put("/scim/v2/Users/{user_id}", dependencies=[Depends(authenticate)])
    async def replace_user(user_id: str, request: Request):
        current = get_or_404(user_id)
        body = await request.json()
        was_active = current.get("active", True)
        replaced = {**body, "id": user_id, "meta": current["meta"]}
        users[user_id] = stamp(replaced)
        if was_active and replaced.get("active") is False:
            notify_deprovisioned(replaced, "PUT active=false")
        return respond(replaced)

    @app.patch("/scim/v2/Users/{user_id}", dependencies=[Depends(authenticate)])
    async def patch_user(user_id: str, request: Request):
        user = get_or_404(user_id)
        body = await request.json()
        if PATCH_SCHEMA not in body.get("schemas", []):
            raise SCIMException(400, "PatchOp schema required", "invalidSyntax")
        was_active = user.get("active", True)
        for op in body.get("Operations", []):
            kind = op.get("op", "").lower()
            if kind not in ("replace", "add"):
                raise SCIMException(400, f"op {kind!r} not supported", "invalidSyntax")
            # Okta sends {"op":"replace","value":{"active":false}}; Entra sends a path.
            if "path" in op:
                user[op["path"]] = op["value"]
            elif isinstance(op.get("value"), dict):
                user.update(op["value"])
        stamp(user)
        if was_active and user.get("active") is False:
            notify_deprovisioned(user, "PATCH active=false")
        return respond(user)

    @app.delete("/scim/v2/Users/{user_id}", dependencies=[Depends(authenticate)], status_code=204)
    def delete_user(user_id: str):
        user = users.pop(user_id, None)
        if user is None:
            raise SCIMException(404, f"user {user_id} not found")
        notify_deprovisioned(user, "DELETE")
        return JSONResponse(None, status_code=204)

    return app
