"""The GuardRail decision engine.

Runs every detector over a proposed action, folds the findings into a single
verdict, and (optionally) writes the decision to the hash-chained audit log.

Verdict rules, in priority order — earlier rules win:

1. Any finding with effect ``block``        → BLOCK
2. Any finding with effect ``escalate``     → ESCALATE_TO_HUMAN
3. Any finding with effect ``conditions``   → APPROVE_WITH_CONDITIONS
4. No findings                              → APPROVE

The engine is deterministic and LLM-free by design: the same action under the
same policy always gets the same verdict, in well under a millisecond.
"""

from __future__ import annotations

from typing import Any, Optional, Union

from .audit import AuditLog
from .detectors import ALL_DETECTORS
from .models import ActionRequest, Decision, Finding, Verdict
from .policy import Policy

_SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 35, "critical": 60}

_CONDITIONS: dict[str, str] = {
    "bulk_operation": "Process in batches with a dry-run preview before the full run",
    "destructive": "Take a verified backup or snapshot before executing",
    "injection": "Re-state the instruction in your own words and confirm it matches the user's request",
}


class Guardrail:
    """Evaluate agent actions against a policy before they execute.

    Usage::

        guard = Guardrail()                       # default policy
        decision = guard.evaluate({
            "tool": "payments", "operation": "payment",
            "parameters": {"amount": 42000}, "agent_role": "support",
        })
        if decision.allowed:
            run_the_tool()
    """

    def __init__(
        self,
        policy: Optional[Union[Policy, dict[str, Any]]] = None,
        audit_log: Optional[AuditLog] = None,
        *,
        fail_closed: bool = True,
    ) -> None:
        if policy is None:
            policy = Policy()
        elif isinstance(policy, dict):
            policy = Policy(policy)
        self.policy = policy
        self.audit_log = audit_log
        self.fail_closed = fail_closed

    # ------------------------------------------------------------------ API

    def evaluate(self, action: Union[ActionRequest, dict[str, Any]]) -> Decision:
        if isinstance(action, dict):
            action = ActionRequest.from_dict(action)
        try:
            findings: list[Finding] = []
            for detector in ALL_DETECTORS:
                findings.extend(detector(action, self.policy))
            decision = self._decide(action, findings)
        except Exception as exc:  # never let the guard itself crash the caller
            if not self.fail_closed:
                raise
            decision = Decision(
                action_id=action.action_id,
                verdict=Verdict.ESCALATE_TO_HUMAN,
                risk_score=100,
                findings=[Finding(
                    detector="engine",
                    severity="high",
                    message=f"GuardRail evaluation failed ({exc!r}); failing closed.",
                    effect="escalate",
                )],
                explanation="Evaluation error — escalated to a human (fail-closed).",
            )
        if self.audit_log is not None:
            decision.audit_hash = self.audit_log.record(
                action=action.to_dict(), decision=decision.to_dict()
            )
        return decision

    # -------------------------------------------------------------- internals

    @staticmethod
    def _decide(action: ActionRequest, findings: list[Finding]) -> Decision:
        effects = {f.effect for f in findings}
        if "block" in effects:
            verdict = Verdict.BLOCK
        elif "escalate" in effects:
            verdict = Verdict.ESCALATE_TO_HUMAN
        elif "conditions" in effects:
            verdict = Verdict.APPROVE_WITH_CONDITIONS
        else:
            verdict = Verdict.APPROVE

        risk = min(100, sum(_SEVERITY_WEIGHT.get(f.severity, 5) for f in findings))
        if verdict is Verdict.BLOCK:
            risk = max(risk, 80)
        elif verdict is Verdict.ESCALATE_TO_HUMAN:
            risk = max(risk, 50)

        conditions = []
        for f in findings:
            if verdict in (Verdict.APPROVE_WITH_CONDITIONS, Verdict.ESCALATE_TO_HUMAN) \
                    and f.effect == "conditions" and f.detector in _CONDITIONS:
                text = _CONDITIONS[f.detector]
                if text not in conditions:
                    conditions.append(text)

        if not findings:
            explanation = f"{action.operation} on {action.target_resource or action.tool}: no policy issues found."
        else:
            top = max(findings, key=lambda f: _SEVERITY_WEIGHT.get(f.severity, 0))
            explanation = f"{verdict.value}: {top.message}"

        return Decision(
            action_id=action.action_id,
            verdict=verdict,
            risk_score=risk,
            findings=findings,
            conditions=conditions,
            explanation=explanation,
        )
