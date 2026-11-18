"""FastAPI / Starlette integration.

Two ways to protect an app:

1. **Middleware**: guard specific routes that execute agent tool calls. The
   request body is read as an action (``tool``, ``operation``,
   ``target_resource``, ``parameters``, ...). Blocked or escalated actions
   never reach your handler::

       from guardrail_middleware.fastapi import GuardrailMiddleware
       app.add_middleware(GuardrailMiddleware, paths=["/tools/execute"])

   Verdicts are exposed to handlers and clients via response headers
   ``X-Guardrail-Verdict`` and ``X-Guardrail-Risk``. A stopped action returns
   HTTP 403 with the full decision as JSON.

2. **Decorator**: guard a plain Python function that performs a tool call::

       @guard_tool(guard)
       def send_payment(amount: int, to: str): ...

   The wrapped function's arguments become the action parameters; a BLOCK or
   ESCALATE verdict raises :class:`GuardrailBlocked` instead of running.
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .engine import Guardrail
from .models import ActionRequest, Decision


class GuardrailBlocked(Exception):
    """Raised by @guard_tool when GuardRail stops an action."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"GuardRail {decision.verdict.value}: {decision.explanation}")
        self.decision = decision


class GuardrailMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that vets tool-call requests before execution."""

    def __init__(
        self,
        app,
        guard: Optional[Guardrail] = None,
        *,
        paths: Optional[list[str]] = None,
        path_prefix: Optional[str] = None,
    ) -> None:
        super().__init__(app)
        self.guard = guard or Guardrail()
        self.paths = set(paths or [])
        self.path_prefix = path_prefix

    def _guarded(self, path: str) -> bool:
        if self.paths:
            return path in self.paths
        if self.path_prefix:
            return path.startswith(self.path_prefix)
        return True

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method not in ("POST", "PUT", "PATCH", "DELETE") or not self._guarded(request.url.path):
            return await call_next(request)

        raw = await request.body()
        try:
            payload = json.loads(raw) if raw else {}
            if not isinstance(payload, dict):
                raise ValueError("action body must be a JSON object")
            action = ActionRequest.from_dict(payload)
        except Exception:
            # Not an action-shaped body, so it is not ours to judge. Pass through.
            return await call_next(request)

        if not action.tool and not action.operation:
            return await call_next(request)

        decision = self.guard.evaluate(action)
        if not decision.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "guardrail_stopped",
                    "decision": decision.to_dict(),
                },
                headers={
                    "X-Guardrail-Verdict": decision.verdict.value,
                    "X-Guardrail-Risk": str(decision.risk_score),
                },
            )

        response = await call_next(request)
        response.headers["X-Guardrail-Verdict"] = decision.verdict.value
        response.headers["X-Guardrail-Risk"] = str(decision.risk_score)
        return response


def guard_tool(
    guard: Guardrail,
    *,
    tool: str,
    operation: str,
    agent_role: str = "agent",
    target_param: Optional[str] = None,
):
    """Decorator: vet a function's arguments as an action before it runs."""

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            import inspect

            bound = inspect.signature(fn).bind_partial(*args, **kwargs).arguments
            params = {k: v for k, v in bound.items() if k != target_param}
            action = ActionRequest(
                tool=tool,
                operation=operation,
                target_resource=str(bound.get(target_param, "")) if target_param else "",
                parameters=params,
                agent_role=agent_role,
            )
            decision = guard.evaluate(action)
            if not decision.allowed:
                raise GuardrailBlocked(decision)
            return fn(*args, **kwargs)

        return wrapper

    return decorator
