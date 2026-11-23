"""OpenID AuthZEN Authorization API 1.0: access evaluation endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .policy import Policy


class Entity(BaseModel):
    type: str
    id: str
    properties: dict[str, Any] = Field(default_factory=dict)


class Action(BaseModel):
    name: str
    properties: dict[str, Any] = Field(default_factory=dict)


class EvaluationRequest(BaseModel):
    subject: Entity
    action: Action
    resource: Entity
    context: dict[str, Any] = Field(default_factory=dict)


class PartialEvaluation(BaseModel):
    subject: Entity | None = None
    action: Action | None = None
    resource: Entity | None = None
    context: dict[str, Any] | None = None


class EvaluationsRequest(BaseModel):
    subject: Entity | None = None
    action: Action | None = None
    resource: Entity | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    evaluations: list[PartialEvaluation] = Field(default_factory=list)


def create_app(policy: Policy | None = None, issuer: str = "https://pdp.example.test") -> FastAPI:
    policy = policy or Policy()
    app = FastAPI(title="AuthZEN PDP", version="0.1.0")

    def decide(req: EvaluationRequest) -> dict:
        return policy.evaluate(
            req.subject.model_dump(), req.action.model_dump(), req.resource.model_dump(), req.context
        ).to_authzen()

    @app.get("/.well-known/authzen-configuration")
    def metadata() -> dict:
        return {
            "policy_decision_point": issuer,
            "access_evaluation_endpoint": f"{issuer}/access/v1/evaluation",
            "access_evaluations_endpoint": f"{issuer}/access/v1/evaluations",
        }

    @app.post("/access/v1/evaluation")
    def evaluation(req: EvaluationRequest) -> dict:
        return decide(req)

    @app.post("/access/v1/evaluations")
    def evaluations(req: EvaluationsRequest) -> dict:
        # Each item inherits any top-level subject/action/resource/context it omits.
        results = []
        for item in req.evaluations or [PartialEvaluation()]:
            merged = {
                "subject": item.subject or req.subject,
                "action": item.action or req.action,
                "resource": item.resource or req.resource,
                "context": {**req.context, **(item.context or {})},
            }
            if None in (merged["subject"], merged["action"], merged["resource"]):
                results.append({"decision": False, "context": {"reason": "incomplete request"}})
                continue
            results.append(decide(EvaluationRequest(**merged)))
        return {"evaluations": results}

    return app


app = create_app()
