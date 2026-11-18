"""Append-only, hash-chained audit log.

Every decision GuardRail makes is recorded as one JSON line. Each entry
carries the SHA-256 hash of the previous entry, so any later edit, deletion,
or reordering of the log breaks the chain and is detectable with
:meth:`AuditLog.verify`.

The log is deliberately boring: a file on disk, one line per decision, no
database required. Point it at shared storage if several processes write.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

_GENESIS = "0" * 64


def _entry_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """Thread-safe append-only audit log with a SHA-256 hash chain."""

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self._path.exists():
            return _GENESIS
        last = _GENESIS
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["entry_hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    def record(self, *, action: dict[str, Any], decision: dict[str, Any]) -> str:
        """Append one decision; returns the new entry's hash."""
        with self._lock:
            payload = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "prev_hash": self._last_hash,
                "action": action,
                "decision": decision,
            }
            entry_hash = _entry_hash(payload)
            entry = {**payload, "entry_hash": entry_hash}
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._last_hash = entry_hash
            return entry_hash

    def verify(self) -> dict[str, Any]:
        """Recompute the whole chain. Returns {ok, entries, broken_at}."""
        prev = _GENESIS
        count = 0
        if not self._path.exists():
            return {"ok": True, "entries": 0, "broken_at": None}
        with open(self._path, "r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return {"ok": False, "entries": count, "broken_at": idx}
                payload = {k: v for k, v in entry.items() if k != "entry_hash"}
                if entry.get("prev_hash") != prev or _entry_hash(payload) != entry.get("entry_hash"):
                    return {"ok": False, "entries": count, "broken_at": idx}
                prev = entry["entry_hash"]
                count += 1
        return {"ok": True, "entries": count, "broken_at": None}
