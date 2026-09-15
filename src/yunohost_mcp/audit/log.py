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

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yunohost_mcp.redaction import redact as _redact

# The first entry's prev_hash (nothing precedes it). A 64-char value keeps
# every entry's prev_hash uniformly a sha256 hex digest.
_GENESIS_HASH = "0" * 64

# _read_all refuses to slurp unbounded files; beyond this size it reads only
# the most recent tail so list()/get() stay bounded on a growing/corrupt log.
_MAX_READ_BYTES = 64 * 1024 * 1024


@dataclass
class AuditLog:
    """Appends one JSON object per line to `path`. `path`'s parent is created on first write.

    Every entry carries ``prev_hash`` (the previous entry's ``entry_hash``)
    and its own ``entry_hash`` (sha256 over the whole entry minus
    ``entry_hash`` itself), so the file is a hash chain: any edit, deletion,
    reordering, or truncation is detectable via :meth:`verify`. Entries are
    written append-only with ``O_NOFOLLOW`` (a pre-placed symlink at the
    configured path can no longer redirect writes).
    """

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
        request_id: str | None = None,
        execution_context: str | None = None,
    ) -> str:
        audit_id = f"mcp-{uuid.uuid4().hex[:20]}"
        payload: dict[str, Any] = {
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
        if request_id is not None:
            payload["request_id"] = request_id
        if execution_context is not None:
            payload["execution_context"] = execution_context
        payload["prev_hash"] = _last_entry_hash(self.path) or _GENESIS_HASH
        entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        line = json.dumps({**payload, "entry_hash": entry_hash}, default=str) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_NOFOLLOW: a symlink planted at `path` must not redirect writes;
        # O_APPEND guarantees each line is appended atomically for small writes.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o660)
        try:
            with os.fdopen(fd, "a") as f:
                f.write(line)
        finally:
            os.chmod(self.path, 0o660)
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

    def verify(self) -> list[str]:
        """Walk the hash chain and return a list of integrity problems.

        An empty list means the file is intact: every entry's ``entry_hash``
        matches its content and each ``prev_hash`` matches the previous
        entry's hash. A non-empty list describes each detected tamper,
        deletion, reordering, or truncation.
        """
        problems: list[str] = []
        expected_prev = _GENESIS_HASH
        for index, entry in enumerate(self._read_all()):
            stored_hash = entry.get("entry_hash")
            if entry.get("prev_hash") != expected_prev:
                problems.append(f"line {index + 1}: prev_hash mismatch (expected {expected_prev})")
            if not isinstance(stored_hash, str):
                problems.append(f"line {index + 1}: missing entry_hash")
                continue
            without_self = dict(entry)
            without_self.pop("entry_hash", None)
            recomputed = hashlib.sha256(json.dumps(without_self, sort_keys=True, default=str).encode()).hexdigest()
            if stored_hash != recomputed:
                problems.append(f"line {index + 1}: entry_hash does not match content")
            expected_prev = stored_hash
        return problems

    def _read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        size = self.path.stat().st_size
        if size > _MAX_READ_BYTES:
            with self.path.open("rb") as handle:
                handle.seek(size - _MAX_READ_BYTES)
                data = handle.read(_MAX_READ_BYTES).decode("utf-8", "replace")
        else:
            data = self.path.read_text()
        entries = []
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries


def _last_entry_hash(path: Path) -> str | None:
    """The previous entry's ``entry_hash``, read from the file tail."""
    try:
        size = path.stat().st_size
        if size == 0:
            return None
        window = min(size, 1 << 20)
        with path.open("rb") as handle:
            handle.seek(size - window)
            data = handle.read(window).decode("utf-8", "replace")
    except OSError:
        return None
    for line in reversed(data.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        value = entry.get("entry_hash")
        if isinstance(value, str) and value:
            return value
    return None
