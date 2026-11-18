"""Minimal FastAPI app protected by GuardrailMiddleware.

    pip install guardrail-middleware[fastapi] uvicorn
    uvicorn examples.fastapi_app:app --reload

Then try:

    # approved
    curl -X POST localhost:8000/tools/execute -H 'Content-Type: application/json' \
      -d '{"tool":"db","operation":"read","target_resource":"users/42"}'

    # blocked: role 'intern' may not delete
    curl -X POST localhost:8000/tools/execute -H 'Content-Type: application/json' \
      -d '{"tool":"db","operation":"delete","target_resource":"users","agent_role":"intern"}'
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fastapi import FastAPI

from guardrail_middleware import AuditLog, Guardrail
from guardrail_middleware.fastapi import GuardrailMiddleware

guard = Guardrail(audit_log=AuditLog(Path(__file__).parent / "audit.jsonl"))

app = FastAPI(title="Guarded tool executor")
app.add_middleware(GuardrailMiddleware, guard=guard, paths=["/tools/execute"])


@app.post("/tools/execute")
async def execute(payload: dict):
    """In a real deployment this is where the tool actually runs."""
    return {"executed": True, "tool": payload.get("tool"), "operation": payload.get("operation")}
