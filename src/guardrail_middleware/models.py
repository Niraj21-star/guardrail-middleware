"""Core data models for guardrail-middleware.

An *action* is one proposed tool call by an AI agent: which tool, which
operation, on what resource, with what parameters, and where the instruction
came from. GuardRail evaluates the action *before* it executes and returns a
:class:`Decision`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    """Final decision for a proposed action."""

    APPROVE = "APPROVE"
    APPROVE_WITH_CONDITIONS = "APPROVE_WITH_CONDITIONS"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"
    BLOCK = "BLOCK"

    @property
    def allowed(self) -> bool:
        """True when the action may proceed (possibly with conditions)."""
        return self in (Verdict.APPROVE, Verdict.APPROVE_WITH_CONDITIONS)


class TriggeredBy(str, Enum):
    """Origin of the instruction that produced this action.

    Anything other than a direct user instruction is *untrusted*: content from
    emails, webpages and tool outputs is data, never instructions.
    """

    USER = "user"
    EMAIL = "email"
    WEBPAGE = "webpage"
    TOOL_OUTPUT = "tool_output"
    OTHER = "other"

    @property
    def untrusted(self) -> bool:
        return self is not TriggeredBy.USER


@dataclass
class ActionRequest:
    """A single proposed agent action, submitted for pre-execution validation."""

    tool: str
    operation: str
    target_resource: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    agent_id: str = "agent"
    agent_role: str = "agent"
    stated_reason: str = ""
    task_context: str = ""
    triggered_by: TriggeredBy = TriggeredBy.USER
    source_text: Optional[str] = None
    action_id: str = field(default_factory=lambda: f"act-{uuid.uuid4().hex[:8]}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionRequest":
        triggered = data.get("triggered_by", TriggeredBy.USER)
        if isinstance(triggered, str):
            triggered = TriggeredBy(triggered.lower())
        return cls(
            tool=str(data.get("tool", "")),
            operation=str(data.get("operation", "")),
            target_resource=str(data.get("target_resource", "")),
            parameters=dict(data.get("parameters") or {}),
            agent_id=str(data.get("agent_id", "agent")),
            agent_role=str(data.get("agent_role", "agent")),
            stated_reason=str(data.get("stated_reason", "")),
            task_context=str(data.get("task_context", "")),
            triggered_by=triggered,
            source_text=data.get("source_text"),
            action_id=str(data.get("action_id") or f"act-{uuid.uuid4().hex[:8]}"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "agent_role": self.agent_role,
            "tool": self.tool,
            "operation": self.operation,
            "target_resource": self.target_resource,
            "parameters": self.parameters,
            "stated_reason": self.stated_reason,
            "task_context": self.task_context,
            "triggered_by": self.triggered_by.value,
        }


@dataclass
class Finding:
    """One detector hit: what fired, how bad it is, and what to do about it."""

    detector: str
    severity: str  # "low" | "medium" | "high" | "critical"
    message: str
    effect: str = "warn"  # "warn" | "conditions" | "escalate" | "block"


@dataclass
class Decision:
    """The verdict on an action, with the evidence behind it."""

    action_id: str
    verdict: Verdict
    risk_score: int  # 0 (safe) .. 100 (certain harm)
    findings: list[Finding] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    explanation: str = ""
    audit_hash: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.verdict.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "verdict": self.verdict.value,
            "allowed": self.allowed,
            "risk_score": self.risk_score,
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity,
                    "message": f.message,
                    "effect": f.effect,
                }
                for f in self.findings
            ],
            "conditions": self.conditions,
            "explanation": self.explanation,
            "audit_hash": self.audit_hash,
        }
