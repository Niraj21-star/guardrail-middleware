"""Middleware + decorator tests using a real FastAPI app and TestClient."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardrail_middleware import Guardrail
from guardrail_middleware.fastapi import GuardrailBlocked, GuardrailMiddleware, guard_tool


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.add_middleware(GuardrailMiddleware, paths=["/tools/execute"])

    @app.post("/tools/execute")
    async def execute(payload: dict):
        return {"executed": True, "tool": payload.get("tool")}

    @app.get("/health")
    async def health():
        return {"ok": True}

    return TestClient(app)


def test_safe_action_reaches_handler(client):
    r = client.post("/tools/execute", json={
        "tool": "db", "operation": "read", "target_resource": "users/42",
    })
    assert r.status_code == 200
    assert r.json()["executed"] is True
    assert r.headers["X-Guardrail-Verdict"] == "APPROVE"


def test_blocked_action_never_reaches_handler(client):
    r = client.post("/tools/execute", json={
        "tool": "db", "operation": "delete", "target_resource": "users",
        "agent_role": "intern",
    })
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "guardrail_stopped"
    assert body["decision"]["verdict"] == "BLOCK"


def test_escalated_action_is_stopped_with_verdict(client):
    r = client.post("/tools/execute", json={
        "tool": "payments", "operation": "payment",
        "parameters": {"amount": 42_000}, "agent_role": "finance",
    })
    assert r.status_code == 403
    assert r.json()["decision"]["verdict"] == "ESCALATE_TO_HUMAN"


def test_unguarded_path_passes_through(client):
    r = client.get("/health")
    assert r.status_code == 200


def test_guard_tool_decorator_blocks():
    guard = Guardrail()
    calls = []

    @guard_tool(guard, tool="payments", operation="payment", agent_role="support")
    def send_payment(amount: int, to: str):
        calls.append((amount, to))
        return "sent"

    with pytest.raises(GuardrailBlocked):
        send_payment(amount=42_000, to="vendor/acme")
    assert calls == []  # the function never ran

    @guard_tool(guard, tool="payments", operation="payment", agent_role="finance")
    def small_payment(amount: int, to: str):
        return "sent"

    assert small_payment(amount=100, to="vendor/acme") == "sent"
