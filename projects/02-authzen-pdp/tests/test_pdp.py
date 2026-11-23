import pytest
from fastapi.testclient import TestClient

from authzen_pdp.app import create_app
from authzen_pdp.policy import Policy, load_default_policy


@pytest.fixture
def client():
    return TestClient(create_app())


def req(tool, scopes, subject_type="agent", acting_for="user:alice", **context):
    return {
        "subject": {
            "type": subject_type,
            "id": "agent:helpdesk-bot",
            "properties": {"scopes": scopes, "acting_for": acting_for},
        },
        "action": {"name": "tools/call"},
        "resource": {"type": "tool", "id": tool},
        "context": context,
    }


def test_metadata(client):
    body = client.get("/.well-known/authzen-configuration").json()
    assert body["access_evaluation_endpoint"].endswith("/access/v1/evaluation")


@pytest.mark.parametrize(
    ("payload", "allowed", "rule"),
    [
        (req("tickets.read", ["tickets.read"]), True, "allow"),
        (req("tickets.read", []), False, "scope"),
        (req("nope", ["tickets.read"]), False, "known-tool"),
        (req("admin.export_users", ["admin.export"]), False, "agent-forbidden"),
        (req("tickets.read", ["tickets.read"], acting_for=None), False, "delegation-required"),
        (req("payments.refund", ["payments.refund"]), False, "step-up-approval"),
        (
            req("payments.refund", ["payments.refund"], human_approval=True, arguments={"amount": 50}),
            True,
            "allow",
        ),
        (
            req("payments.refund", ["payments.refund"], human_approval=True, arguments={"amount": 5000}),
            False,
            "amount-limit",
        ),
    ],
)
def test_single_evaluation(client, payload, allowed, rule):
    body = client.post("/access/v1/evaluation", json=payload).json()
    assert body["decision"] is allowed
    assert body["context"]["rule"] == rule


def test_batch_inherits_top_level_fields(client):
    base = req("tickets.read", ["tickets.read"])
    body = client.post(
        "/access/v1/evaluations",
        json={
            "subject": base["subject"],
            "action": base["action"],
            "evaluations": [
                {"resource": {"type": "tool", "id": "tickets.read"}},
                {"resource": {"type": "tool", "id": "tickets.comment"}},
            ],
        },
    ).json()
    assert [e["decision"] for e in body["evaluations"]] == [True, False]


def test_device_posture_rule():
    doc = load_default_policy()
    doc["require_device_posture_for_high_risk"] = True
    client = TestClient(create_app(Policy(doc)))
    payload = req("payments.refund", ["payments.refund"], human_approval=True, device={"posture": "unknown"})
    assert client.post("/access/v1/evaluation", json=payload).json()["context"]["rule"] == "device"
    payload["context"]["device"] = {"posture": "compliant"}
    assert client.post("/access/v1/evaluation", json=payload).json()["decision"] is True
