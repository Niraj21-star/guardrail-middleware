# guardrail-middleware

**Runtime authorization for AI agent tool calls.** GuardRail sits between an AI agent and its tools: every proposed action is checked against a policy *before* it executes, and every decision is written to a tamper-evident audit log.

An agent that can call tools can also be talked into misusing them: by a prompt injection in an email, a poisoned webpage, or its own overconfidence. GuardRail is the checkpoint that asks, deterministically and in under a millisecond: *is this role allowed to do this, to this resource, with these parameters, on the say-so of this source?*

```
pip install guardrail-middleware            # core, zero dependencies
pip install guardrail-middleware[fastapi]   # + FastAPI/Starlette middleware
```

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Niraj21-star/guardrail-middleware/blob/main/examples/guardrail_middleware_demo.ipynb) Try the 2-minute demo in your browser: five scenarios, the injection attack up close, and an editable cell to test your own cases.

## Quick start: framework-agnostic

```python
from guardrail_middleware import Guardrail

guard = Guardrail()  # built-in default policy

decision = guard.evaluate({
    "tool": "payments",
    "operation": "payment",
    "target_resource": "vendor/acme",
    "parameters": {"amount": 42000},
    "agent_role": "support",
})

decision.verdict   # Verdict.BLOCK (role 'support' may not run payments)
decision.allowed   # False
decision.explanation
```

Works anywhere an agent proposes an action: LangChain/LangGraph tool wrappers, MCP servers, custom agent loops, job queues.

Tool names work as-is, too. If an action names only a tool, GuardRail classifies it from the name: `send_payment`, `stripe_refund`, `delete_user` and `get_order_status` are all understood (`params` is accepted as an alias for `parameters`, `source_type` for `triggered_by`).

## Quick start: FastAPI / Starlette middleware

```python
from fastapi import FastAPI
from guardrail_middleware import Guardrail, AuditLog
from guardrail_middleware.fastapi import GuardrailMiddleware

app = FastAPI()
app.add_middleware(
    GuardrailMiddleware,
    guard=Guardrail(audit_log=AuditLog("audit.jsonl")),
    paths=["/tools/execute"],
)
```

Requests to guarded paths are read as actions. **Blocked or escalated actions never reach your handler**. The client gets HTTP 403 with the full decision as JSON. Allowed actions pass through with `X-Guardrail-Verdict` and `X-Guardrail-Risk` headers set.

## Quick start: decorator

```python
from guardrail_middleware.fastapi import guard_tool, GuardrailBlocked

@guard_tool(guard, tool="payments", operation="payment", agent_role="support")
def send_payment(amount: int, to: str):
    ...  # only runs if GuardRail approves

try:
    send_payment(amount=42_000, to="vendor/acme")
except GuardrailBlocked as stopped:
    print(stopped.decision.explanation)
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `APPROVE` | No policy issues. Execute. |
| `APPROVE_WITH_CONDITIONS` | Execute only with the attached conditions (batch it, back up first, dry-run). |
| `ESCALATE_TO_HUMAN` | A person must approve first (over-limit payment, untrusted source, unbounded delete). |
| `BLOCK` | Never execute (injection, unauthorized role, PII exfiltration, hard money ceiling). |

Priority is fail-safe: any `block` finding wins, then `escalate`, then `conditions`.

## What it checks: 7 deterministic detectors

No LLM in the decision path: the same action under the same policy always gets the same verdict, reproducibly and fast.

1. **Injection**: instruction-override / role-hijack / secret-extraction / policy-bypass patterns in untrusted content (email, webpage, tool output). Untrusted content is data, never instructions.
2. **Authorization**: role × operation-class permissions (an `intern` role cannot delete, a `support` role cannot pay).
3. **Financial limits**: per-class auto-approve and block thresholds, plus a hard ceiling no role can exceed; a payment with no verifiable amount escalates.
4. **Bulk operations**: record-count thresholds: conditions (batch + dry-run) above the auto-approve max, escalation above the bulk ceiling.
5. **Taint / exfiltration**: PII or secret fields flowing to an external destination is blocked; secrets inside tool-call parameters are blocked outright.
6. **Destructive actions**: irreversible operations without a backup/confirmation marker get conditions; a delete with no target escalates.
7. **Untrusted source**: money movement, deletion, or external sends *triggered by* email/webpage/tool-output content escalate to a human.

## Policy

Every threshold lives in one policy dict. Tune it without touching code, or load it from YAML:

```python
from guardrail_middleware import Guardrail, Policy

policy = Policy.from_yaml("policy.yaml")   # see policy.example.yaml
guard = Guardrail(policy=policy)

# …or inline
guard = Guardrail(policy={"approval_limits": {"payment": {"auto_approve_max": 500}}})
```

## Audit log

Pass an `AuditLog` and every decision is appended as one JSON line, hash-chained with SHA-256: each entry commits to the previous entry's hash, so editing, deleting, or reordering history breaks the chain.

```python
from guardrail_middleware import AuditLog
AuditLog("audit.jsonl").verify()   # {'ok': True, 'entries': 128, 'broken_at': None}
```

## Demo & tests

```bash
python examples/demo.py     # 5 scenarios, all four verdicts, audit verification
pytest                      # 20 tests: engine, detectors, middleware, decorator, audit tampering
```

## Where this comes from

`guardrail-middleware` is the reusable enforcement core extracted from **[GuardRail](https://github.com/Niraj21-star/guard_ai)**, a runtime action-authorization and behavioral-safety layer for agentic AI built at Infosys Ignite EngNext 2026 (special recognition), where the full system adds multi-step plan validation, an action-passport execution gateway, and a 42-scenario adversarial red-team benchmark. It packages the single-action checkpoint from that system so any agent stack can adopt it in minutes.

## Status & honesty notes

- v0.1.1, alpha. The API may still move.
- Detectors are deterministic heuristics, not a proof of safety. Pair them with least-privilege credentials and human review for high-impact tools.
- Plan-level (multi-step) validation lives in the main GuardRail project, not in this package yet.

## License

MIT © Niraj Sanjay Karnawat
