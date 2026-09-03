"""Minimal audit trail for write operations (PLAN.md Phase 5/10, partial).

This is the write side only: one JSON-lines file, one entry per write tool
call, with the initiating pubkey, arguments (redacted), and outcome. Reading
it back (audit_list/audit_get as administrator-only tools) is full Phase 10
and not implemented yet — PLAN.md's example audit entry also includes
policy-decision and confirmation-id fields that don't exist until Phase 6/7
land; this is intentionally a subset, not a preview of the final shape.

Redaction here is a first, narrow pass (key-name matching only) — PLAN.md
Phase 9 wants central response filtering across every tool's *output* too,
not just what gets written to this log.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REDACT_KEYS = {
    "password",
    "secret",
    "token",
    "private_key",
    "api_key",
    "db_password",
    "ldap_password",
    "session",
    "cookie",
    "nsec",
}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


@dataclass
class AuditLog:
    """Appends one JSON object per line to `path`. `path`'s parent is created on first write."""

    path: Path

    def record(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        caller_pubkey: str,
        decision: str,
        result: str,
        yunohost_operation: str | None = None,
        error: str | None = None,
    ) -> str:
        audit_id = f"mcp-{uuid.uuid4().hex[:20]}"
        entry = {
            "audit_id": audit_id,
            "timestamp": time.time(),
            "caller": caller_pubkey,
            "tool": tool,
            "arguments": _redact(arguments),
            "decision": decision,
            "yunohost_operation": yunohost_operation,
            "result": result,
            "error": error,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return audit_id
