"""Policy configuration for guardrail-middleware.

The policy is a plain dict (loaded from YAML if PyYAML is installed, or built
in code). Every threshold the detectors use lives here, so a team can tighten
or loosen GuardRail without touching code.

The defaults mirror the reference GuardRail policy used in the original
project's red-team benchmark.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Optional, Union

DEFAULT_POLICY: dict[str, Any] = {
    # Roles allowed to perform each operation class. "*" = any role.
    "role_permissions": {
        "read": ["*"],
        "write": ["*"],
        "delete": ["admin", "operator"],
        "payment": ["admin", "finance"],
        "refund": ["admin", "finance"],
        "external_send": ["admin", "operator", "support"],
    },
    # Money limits (in the policy's currency unit, INR by default).
    "approval_limits": {
        "payment": {"auto_approve_max": 5_000, "block_above": 50_000},
        "refund": {"auto_approve_max": 10_000, "block_above": 100_000},
    },
    # Bulk-operation limits, by record count found in parameters.
    "bulk_operation": {"auto_approve_max_records": 50, "escalate_above_records": 500},
    # Parameter keys that count as PII / secrets for taint tracking.
    "pii_fields": [
        "email", "phone", "address", "ssn", "national_id", "passport",
        "credit_card", "bank_account", "date_of_birth", "salary", "medical",
    ],
    "secret_fields": ["api_key", "password", "secret", "token", "private_key"],
    # Operations considered irreversible (no undo). The destructive detector
    # attaches backup/confirmation conditions to these. Money movement is
    # governed by approval_limits instead, so payment/refund are not listed.
    "irreversible_operations": ["delete", "drop", "purge", "truncate", "wipe", "send"],
    # Hosts/patterns treated as internal; anything else is an external destination.
    "internal_hosts": ["localhost", "127.0.0.1", "internal", ".local", ".corp", ".internal"],
    # Hard ceiling: a single action may never move more than this, whatever the role.
    "hard_block_amount": 100_000,
}


class Policy:
    """Thin wrapper around the policy dict with typed helpers."""

    def __init__(self, data: Optional[dict[str, Any]] = None) -> None:
        self._data: dict[str, Any] = copy.deepcopy(DEFAULT_POLICY)
        if data:
            self._deep_merge(self._data, data)

    # ------------------------------------------------------------------ I/O

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "Policy":
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Loading a YAML policy needs PyYAML: pip install pyyaml"
            ) from exc
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping at the top level")
        return cls(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        return cls(data)

    @staticmethod
    def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> None:
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                Policy._deep_merge(target[key], value)
            else:
                target[key] = value

    # -------------------------------------------------------------- helpers

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def role_allowed(self, operation_class: str, role: str) -> Optional[bool]:
        """True/False if the policy names this class; None if unlisted."""
        perms = self.get("role_permissions", operation_class)
        if perms is None:
            return None
        return "*" in perms or role in perms

    @property
    def pii_fields(self) -> set[str]:
        return {str(f).lower() for f in self.get("pii_fields", default=[])}

    @property
    def secret_fields(self) -> set[str]:
        return {str(f).lower() for f in self.get("secret_fields", default=[])}

    @property
    def irreversible_operations(self) -> set[str]:
        ops = set()
        for raw in self.get("irreversible_operations", default=[]):
            for token in re.split(r"[_\-\s]+", str(raw).lower()):
                if token:
                    ops.add(token)
        return ops

    @property
    def internal_hosts(self) -> list[str]:
        return [str(h).lower() for h in self.get("internal_hosts", default=[])]
