"""Audit trail for write operations (PLAN.md Phase 5/10).

One JSON-lines file, one entry per write tool call, with the initiating
pubkey, arguments (redacted), and outcome. `list`/`get` (Phase 10) back
audit_list()/audit_get() in server.py, gated administrator-only via
Scope.AUDIT_READ - not full parity with PLAN.md's example audit entry
(no separate policy-decision field; "decision" is always "allowed" since
a denied call never reaches @audited_write - see its docstring) but the
same shape `record()` has always written, just read back.

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
        approved_by: str | None = None,
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
            # Owner co-signing (owner-approval-plan.md): who approved this
            # operation via approve_operation, when it was gated by
            # require_owner_signature - None for every other write, and for
            # this same operation's own confirmation_pending/error outcomes
            # before an approval existed yet. Lets an audit_list/audit_get
            # reader see both "who ran this" and "who authorized it" from
            # one entry, without cross-referencing the separate
            # owner.approve entry by confirmation_id.
            "approved_by": approved_by,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return audit_id

    def list(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Newest-first, matching yunohost.log.log_list()'s own convention."""
        entries = self._read_all()
        entries.reverse()
        return entries[:limit] if limit is not None else entries

    def get(self, audit_id: str) -> dict[str, Any] | None:
        for entry in self._read_all():
            if entry.get("audit_id") == audit_id:
                return entry
        return None

    def _read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
        return entries
