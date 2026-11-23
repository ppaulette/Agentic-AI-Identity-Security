"""A small, deny-by-default policy for agent tool calls.

Rules run in order and the first failing rule decides. Every decision carries a
reason so the gateway can log it and an engineer can explain it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str

    def to_authzen(self) -> dict:
        return {"decision": self.allowed, "context": {"reason": self.reason, "rule": self.rule}}


def load_default_policy() -> dict:
    return json.loads(resources.files("authzen_pdp").joinpath("policy.json").read_text())


class Policy:
    def __init__(self, document: dict | None = None) -> None:
        self.doc = document or load_default_policy()

    def tool(self, name: str) -> dict | None:
        return self.doc["tools"].get(name)

    def evaluate(self, subject: dict, action: dict, resource: dict, context: dict) -> Decision:
        props = subject.get("properties", {}) or {}
        tool_name = resource.get("id", "")
        tool = self.tool(tool_name)

        if subject.get("type") not in ("agent", "user"):
            return Decision(False, "unknown subject type", "subject-type")
        if action.get("name") != "tools/call":
            return Decision(False, f"action {action.get('name')!r} is not governed here", "action")
        if resource.get("type") != "tool" or tool is None:
            return Decision(False, f"unknown tool {tool_name!r}", "known-tool")

        if subject["type"] == "agent":
            if tool_name in self.doc["agent_forbidden_tools"]:
                return Decision(False, f"{tool_name} is never callable by agents", "agent-forbidden")
            if not props.get("acting_for"):
                return Decision(False, "agent call has no delegating user", "delegation-required")

        scopes = set(props.get("scopes", []))
        if tool["scope"] not in scopes:
            return Decision(False, f"token lacks scope {tool['scope']}", "scope")

        if tool["risk"] == "high":
            if not context.get("human_approval"):
                return Decision(False, f"{tool_name} needs human approval", "step-up-approval")
            if self.doc.get("require_device_posture_for_high_risk"):
                posture = (context.get("device") or {}).get("posture")
                if posture != "compliant":
                    return Decision(False, "high-risk call from a non-compliant device", "device")

        limit = tool.get("max_amount")
        amount = (context.get("arguments") or {}).get("amount")
        if limit is not None and amount is not None and float(amount) > limit:
            return Decision(False, f"amount {amount} exceeds limit {limit}", "amount-limit")

        return Decision(True, "all rules passed", "allow")
