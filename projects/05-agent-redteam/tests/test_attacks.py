import pytest

from agentlab import build_lab
from redteam.attacks import ATTACKS
from redteam.report import to_markdown

# Each attack must be stopped by the control it targets, not by an unrelated failure.
EXPECTED_EVIDENCE = {
    "A01": "cnf.jkt",
    "A02": "DPoP-bound access token required",
    "A03": "DPoP proof replayed",
    "A04": "audience",
    "A05": "expired",
    "A06": "'none' not allowed",
    "A07": "Signature verification failed",
    "A08": "agent authentication failed",
    "A09": "actor assertion replayed",
    "A10": "granted only: tickets.read",
    "A11": "not registered for this resource",
    "A12": "subject token rejected",
    "A13": "never callable by agents",
    "A14": "needs human approval",
    "A15": "needs human approval",
    "A16": "exceeds limit",
    "A17": "no longer active",
    "A18": "no longer active",
}


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.id for a in ATTACKS])
def test_attack_is_blocked_by_intended_control(attack):
    outcome = attack.run(build_lab())
    assert outcome.blocked, f"{attack.id} {attack.name}: {outcome.evidence}"
    assert EXPECTED_EVIDENCE[attack.id] in outcome.evidence, outcome.evidence


def test_controls_are_not_vacuous():
    """The same flows succeed when nobody is attacking, so blocks above are real."""
    lab = build_lab()
    token = lab.token("alice", ["support"], ["tickets.read"])
    assert lab.call(token, "tickets.read", {"ticket_id": "T-100"}).status_code == 200
    fin = lab.token("frank", ["finance"], ["payments.refund"])
    approval = lab.approve("frank", "payments.refund")
    assert lab.call(fin, "payments.refund", {"ticket_id": "T-200", "amount": 40}, approval).status_code == 200


def test_report_renders():
    from redteam.attacks import Outcome

    md = to_markdown([(ATTACKS[0], Outcome(True, "HTTP 401: x|y"))])
    assert "1 of 1 attacks blocked" in md and "x\\|y" in md
