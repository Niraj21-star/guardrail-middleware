"""Deterministic detectors for guardrail-middleware.

Each detector inspects one :class:`ActionRequest` and returns zero or more
:class:`Finding` objects. Detectors are pure functions of (action, policy) —
no network, no LLM — so a decision is reproducible and fast enough to sit in
front of every tool call.

The set mirrors the attack classes from the GuardRail red-team benchmark:
prompt injection, taint/PII exfiltration, unauthorized or destructive actions,
financial-limit abuse, and bulk-operation abuse.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Optional

from .models import ActionRequest, Finding
from .policy import Policy

# ---------------------------------------------------------------------------
# Operation classification
# ---------------------------------------------------------------------------

_READ = {"read", "get", "list", "fetch", "search", "query", "select", "view"}
_WRITE = {"write", "create", "update", "insert", "upsert", "patch", "post"}
_DELETE = {"delete", "drop", "purge", "truncate", "wipe", "erase", "destroy", "remove"}
_PAYMENT = {"payment", "pay", "transfer", "wire", "charge", "send money"}
_REFUND = {"refund", "reimburse", "chargeback"}
_SEND = {"send", "email", "post message", "publish", "webhook", "notify"}


def _tokens(operation: str) -> list[str]:
    """Split an operation name into word tokens.

    ``send_payment`` -> ["send", "payment"], ``processPayment`` ->
    ["process", "payment"], ``getUserById`` -> ["get", "user", "by", "id"].
    """
    spaced = re.sub(r"[_\-\s]+", " ", operation.strip().lower())
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
    return spaced.split()


def classify_operation(operation: str) -> str:
    """Map a free-form operation string to a policy class.

    Accepts the canonical verbs (``payment``, ``refund``, ``delete`` …) and
    real-world tool names (``send_payment``, ``stripe_refund``,
    ``delete_user``): the name is tokenised and the highest-risk class found
    wins — payment/refund outrank external_send, which outranks delete,
    write, then read. A name with no recognisable token stays ``other``.
    """
    tokens = _tokens(operation)
    token_set = set(tokens)
    if token_set & (_PAYMENT | _REFUND):
        return "refund" if token_set & _REFUND else "payment"
    if token_set & _DELETE:
        return "delete"
    if token_set & _SEND:
        return "external_send"
    if token_set & _WRITE:
        return "write"
    if token_set & _READ:
        return "read"
    if token_set & {"execute", "run", "call", "invoke"}:
        return "other"
    return "other"


# ---------------------------------------------------------------------------
# Parameter helpers
# ---------------------------------------------------------------------------

_AMOUNT_KEYS = ("amount", "total", "total_amount", "price", "value", "sum")
_COUNT_KEYS = ("count", "records", "num_records", "batch_size", "limit", "quantity")
_LIST_KEYS = ("ids", "recipients", "targets", "items", "records", "users")


def extract_amount(params: dict[str, Any]) -> Optional[float]:
    for key in _AMOUNT_KEYS:
        val = params.get(key)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return float(val)
    return None


def extract_record_count(params: dict[str, Any]) -> Optional[int]:
    for key in _COUNT_KEYS:
        val = params.get(key)
        if isinstance(val, int) and not isinstance(val, bool):
            return val
    for key in _LIST_KEYS:
        val = params.get(key)
        if isinstance(val, list):
            return len(val)
    return None


def _flatten_keys(obj: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path
            yield from _flatten_keys(value, path)
    elif isinstance(obj, list):
        for item in obj:
            yield from _flatten_keys(item, prefix)


def _present_fields(params: dict[str, Any], wanted: set[str]) -> set[str]:
    found = set()
    for path in _flatten_keys(params):
        leaf = path.rsplit(".", 1)[-1].lower()
        if leaf in wanted:
            found.add(leaf)
    return found


def is_external_destination(resource: str, policy: Policy) -> bool:
    """A resource is external if it looks like a URL/host outside the internal list."""
    res = (resource or "").lower()
    if not res:
        return False
    if not any(marker in res for marker in ("://", ".com", ".io", ".net", ".org", "@")):
        return False  # internal path / table / id
    return not any(host in res for host in policy.internal_hosts)


# ---------------------------------------------------------------------------
# 1. Prompt-injection detector
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction override", re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I)),
    ("instruction override", re.compile(r"disregard (the )?(system|previous|prior)", re.I)),
    ("role hijack", re.compile(r"you are now (a|an|in)\b", re.I)),
    ("role hijack", re.compile(r"\bdeveloper mode\b|\bjailbreak\b|\bDAN mode\b", re.I)),
    ("secret extraction", re.compile(r"(reveal|print|show|leak|dump).{0,30}(system prompt|api key|password|secret|credentials)", re.I)),
    ("policy bypass", re.compile(r"without (telling|notifying|alerting|logging|approval)", re.I)),
    ("policy bypass", re.compile(r"(skip|bypass|override) (the )?(approval|check|verification|guardrail|policy)", re.I)),
    ("urgency pressure", re.compile(r"(urgent|immediately).{0,40}(transfer|send|pay|delete)", re.I)),
]


def detect_injection(action: ActionRequest, policy: Policy) -> list[Finding]:
    texts = [action.source_text or "", action.stated_reason or ""]
    hits = set()
    for text in texts:
        for label, pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                hits.add(label)
    if not hits:
        return []
    labels = ", ".join(sorted(hits))
    if action.triggered_by.untrusted:
        return [Finding(
            detector="injection",
            severity="critical",
            message=f"Prompt-injection pattern(s) in untrusted {action.triggered_by.value} content: {labels}. "
                    "Untrusted content is data, never instructions.",
            effect="block",
        )]
    return [Finding(
        detector="injection",
        severity="medium",
        message=f"Injection-like phrasing in the action rationale: {labels}.",
        effect="conditions",
    )]


# ---------------------------------------------------------------------------
# 2. Authorization detector
# ---------------------------------------------------------------------------

def detect_unauthorized(action: ActionRequest, policy: Policy) -> list[Finding]:
    op_class = classify_operation(action.operation)
    allowed = policy.role_allowed(op_class, action.agent_role)
    if allowed is False:
        return [Finding(
            detector="authorization",
            severity="critical",
            message=f"Role '{action.agent_role}' is not permitted to perform '{op_class}' operations.",
            effect="block",
        )]
    return []


# ---------------------------------------------------------------------------
# 3. Financial-limit detector
# ---------------------------------------------------------------------------

def detect_financial(action: ActionRequest, policy: Policy) -> list[Finding]:
    op_class = classify_operation(action.operation)
    if op_class not in ("payment", "refund"):
        return []
    amount = extract_amount(action.parameters)
    if amount is None:
        return [Finding(
            detector="financial_limits",
            severity="high",
            message=f"{op_class} action carries no amount in its parameters; the value cannot be verified.",
            effect="escalate",
        )]
    findings: list[Finding] = []
    hard_block = policy.get("hard_block_amount")
    if hard_block is not None and amount > float(hard_block):
        findings.append(Finding(
            detector="financial_limits",
            severity="critical",
            message=f"Amount {amount:,.0f} exceeds the hard block ceiling of {float(hard_block):,.0f}.",
            effect="block",
        ))
        return findings
    limits = policy.get("approval_limits", op_class, default={}) or {}
    block_above = limits.get("block_above")
    auto_max = limits.get("auto_approve_max")
    if block_above is not None and amount > float(block_above):
        findings.append(Finding(
            detector="financial_limits",
            severity="critical",
            message=f"{op_class} of {amount:,.0f} exceeds the policy block threshold of {float(block_above):,.0f}.",
            effect="block",
        ))
    elif auto_max is not None and amount > float(auto_max):
        findings.append(Finding(
            detector="financial_limits",
            severity="high",
            message=f"{op_class} of {amount:,.0f} exceeds the auto-approve limit of {float(auto_max):,.0f}; a human must approve.",
            effect="escalate",
        ))
    return findings


# ---------------------------------------------------------------------------
# 4. Bulk-operation detector
# ---------------------------------------------------------------------------

def detect_bulk(action: ActionRequest, policy: Policy) -> list[Finding]:
    count = extract_record_count(action.parameters)
    if count is None:
        return []
    auto_max = policy.get("bulk_operation", "auto_approve_max_records", default=50)
    escalate_above = policy.get("bulk_operation", "escalate_above_records", default=500)
    if count > int(escalate_above):
        return [Finding(
            detector="bulk_operation",
            severity="high",
            message=f"Bulk operation touches {count} records, above the escalation threshold of {escalate_above}.",
            effect="escalate",
        )]
    if count > int(auto_max):
        return [Finding(
            detector="bulk_operation",
            severity="medium",
            message=f"Bulk operation touches {count} records (auto-approve max {auto_max}); batch it and dry-run first.",
            effect="conditions",
        )]
    return []


# ---------------------------------------------------------------------------
# 5. Taint / exfiltration detector
# ---------------------------------------------------------------------------

def detect_taint(action: ActionRequest, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    pii = _present_fields(action.parameters, policy.pii_fields)
    secrets = _present_fields(action.parameters, policy.secret_fields)
    external = is_external_destination(action.target_resource, policy)
    op_class = classify_operation(action.operation)
    outbound = op_class in ("external_send", "payment", "refund", "write")

    if secrets:
        findings.append(Finding(
            detector="taint",
            severity="critical",
            message=f"Action parameters contain secret field(s): {', '.join(sorted(secrets))}. "
                    "Secrets must never travel inside tool-call parameters.",
            effect="block",
        ))
    if pii and external and outbound:
        findings.append(Finding(
            detector="taint",
            severity="critical",
            message=f"PII field(s) {', '.join(sorted(pii))} would flow to external destination "
                    f"'{action.target_resource}'. Possible exfiltration chain.",
            effect="block",
        ))
    elif pii and action.triggered_by.untrusted:
        findings.append(Finding(
            detector="taint",
            severity="high",
            message=f"Action touches PII field(s) {', '.join(sorted(pii))} and was triggered by untrusted "
                    f"{action.triggered_by.value} content; a human should confirm it matches the user's intent.",
            effect="escalate",
        ))
    return findings


# ---------------------------------------------------------------------------
# 6. Destructive / irreversibility detector
# ---------------------------------------------------------------------------

def detect_destructive(action: ActionRequest, policy: Policy) -> list[Finding]:
    op = action.operation.strip().lower()
    op_tokens = set(_tokens(op))
    if not (op_tokens & policy.irreversible_operations) and classify_operation(op) != "delete":
        return []
    params = action.parameters
    confirmed = params.get("confirmed") is True or params.get("dry_run") is True
    backed_up = params.get("backup_taken") is True or params.get("snapshot_id")
    if classify_operation(op) == "delete" and not action.target_resource:
        return [Finding(
            detector="destructive",
            severity="high",
            message="Delete operation has no target resource — scope is unbounded.",
            effect="escalate",
        )]
    if not confirmed and not backed_up:
        return [Finding(
            detector="destructive",
            severity="medium",
            message=f"'{action.operation}' is irreversible and carries no backup/confirmation marker.",
            effect="conditions",
        )]
    return []


# ---------------------------------------------------------------------------
# 7. Untrusted-source escalation detector
# ---------------------------------------------------------------------------

def detect_untrusted_source(action: ActionRequest, policy: Policy) -> list[Finding]:
    if not action.triggered_by.untrusted:
        return []
    op_class = classify_operation(action.operation)
    if op_class in ("payment", "refund", "delete", "external_send"):
        return [Finding(
            detector="untrusted_source",
            severity="high",
            message=f"A {op_class} action was triggered by {action.triggered_by.value} content, not by the user. "
                    "Untrusted content must never originate money movement, deletion, or external sends.",
            effect="escalate",
        )]
    return []


ALL_DETECTORS: list[Callable[[ActionRequest, Policy], list[Finding]]] = [
    detect_injection,
    detect_unauthorized,
    detect_financial,
    detect_bulk,
    detect_taint,
    detect_destructive,
    detect_untrusted_source,
]
