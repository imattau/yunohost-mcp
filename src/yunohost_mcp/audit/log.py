"""Minimal audit trail for write operations (PLAN.md Phase 5/10, partial).

This is the write side only: one JSON-lines file, one entry per write tool
call, with the initiating pubkey, arguments (redacted), and outcome. Reading
it back (audit_list/audit_get as administrator-only tools) is full Phase 10
and not implemented yet — PLAN.md's example audit entry also includes
policy-decision and confirmation-id fields that don't exist until Phase 6/7
land; this is intentionally a subset, not a preview of the final shape.

Redaction here reuses redaction.py's shared pass (Phase 9) - the same
key-name matching applied to every tool's *response* too
(server.py's @redact_response on every tool), not a separate policy.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yunohost_mcp.redaction import redact as _redact


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
