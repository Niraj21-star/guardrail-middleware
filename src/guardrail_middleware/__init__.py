"""guardrail-middleware: runtime authorization for AI agent tool calls.

GuardRail sits between an AI agent and its tools. Every proposed action is
checked against a policy (authorization, prompt-injection and taint
detectors, financial and bulk limits) *before* it executes, and every
decision is written to a tamper-evident, hash-chained audit log.

Quick start::

    from guardrail_middleware import Guardrail

    guard = Guardrail()
    decision = guard.evaluate({
        "tool": "payments", "operation": "payment",
        "target_resource": "vendor/acme",
        "parameters": {"amount": 42000},
        "agent_role": "support",
    })
    print(decision.verdict)   # ESCALATE_TO_HUMAN

Extracted from the GuardRail project (Infosys Ignite EngNext 2026, special
recognition) so any agent stack can use the same enforcement core.
"""

from .audit import AuditLog
from .engine import Guardrail
from .models import ActionRequest, Decision, Finding, TriggeredBy, Verdict
from .policy import DEFAULT_POLICY, Policy

__version__ = "0.1.1"

__all__ = [
    "Guardrail",
    "Policy",
    "DEFAULT_POLICY",
    "AuditLog",
    "ActionRequest",
    "Decision",
    "Finding",
    "Verdict",
    "TriggeredBy",
    "__version__",
]
