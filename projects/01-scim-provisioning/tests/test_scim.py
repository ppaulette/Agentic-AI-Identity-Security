import httpx
import pytest
from fastapi.testclient import TestClient

from scim_server.app import PATCH_SCHEMA, USER_SCHEMA, create_app

AUTH = {"Authorization": "Bearer idp-token"}


class FakeBroker:
    def __init__(self):
        self.events = []

    def post(self, url, json, headers):
        self.events.append((url, json, headers))
        return httpx.Response(200, request=httpx.Request("POST", url))


@pytest.fixture
def setup():
    broker = FakeBroker()
    app = create_app("idp-token", broker=broker, broker_url="https://broker", events_secret="s")
    return TestClient(app), broker


def create(client, name="alice"):
    return client.post(
        "/scim/v2/Users", headers=AUTH, json={"schemas": [USER_SCHEMA], "userName": name, "active": True}
    ).json()


def test_requires_bearer(setup):
    client, _ = setup
    r = client.get("/scim/v2/Users")
    assert r.status_code == 401
    assert r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_create_filter_and_uniqueness(setup):
    client, _ = setup
    user = create(client)
    assert user["meta"]["location"].endswith(user["id"])
    listing = client.get("/scim/v2/Users", headers=AUTH, params={"filter": 'userName eq "ALICE"'}).json()
    assert listing["totalResults"] == 1
    dup = client.post("/scim/v2/Users", headers=AUTH, json={"schemas": [USER_SCHEMA], "userName": "alice"})
    assert dup.status_code == 409 and dup.json()["scimType"] == "uniqueness"


@pytest.mark.parametrize(
    "operations",
    [
        [{"op": "replace", "value": {"active": False}}],  # Okta style
        [{"op": "Replace", "path": "active", "value": False}],  # Entra style
    ],
)
def test_deactivation_notifies_broker_once(setup, operations):
    client, broker = setup
    user = create(client)
    body = {"schemas": [PATCH_SCHEMA], "Operations": operations}
    client.patch(f"/scim/v2/Users/{user['id']}", headers=AUTH, json=body)
    client.patch(f"/scim/v2/Users/{user['id']}", headers=AUTH, json=body)  # already inactive
    assert len(broker.events) == 1
    url, payload, headers = broker.events[0]
    assert url == "https://broker/events/user-deprovisioned"
    assert payload == {"user": "user:alice"}
    assert headers == {"X-Event-Secret": "s"}


def test_delete_notifies_broker(setup):
    client, broker = setup
    user = create(client, "bob")
    assert client.delete(f"/scim/v2/Users/{user['id']}", headers=AUTH).status_code == 204
    assert broker.events[0][1] == {"user": "user:bob"}
    assert client.get(f"/scim/v2/Users/{user['id']}", headers=AUTH).status_code == 404


def test_unsupported_filter(setup):
    client, _ = setup
    r = client.get("/scim/v2/Users", headers=AUTH, params={"filter": 'emails co "x"'})
    assert r.status_code == 400 and r.json()["scimType"] == "invalidFilter"
