"""@audited_write: wraps a write tool handler with locking + an audit entry.

Composes with policy/enforcement.py's @require_scope, applied outside it
(`@require_scope(...)` above `@audited_write(...)` in source order, so scope
denial happens first and never reaches this decorator - only authorized
calls get locked, executed, and audited). See PLAN.md Phase 5's "every
operation must" list: this covers "acquire a lock", "record the initiating
Nostr pubkey", "return structured status", and "write an audit entry";
scope-checking is require_scope's job, argument validation is the tool
function's own (via its type hints / adapter method).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from yunohost_mcp.audit.log import AuditLog
from yunohost_mcp.auth.identity import require_current_request
from yunohost_mcp.policy.locks import LockedError, WriteLock

F = TypeVar("F", bound=Callable[..., dict[str, Any]])


def audited_write(tool_name: str, *, lock: WriteLock, audit_log: AuditLog) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            request = require_current_request()
            caller = request.pubkey

            try:
                with lock.locked():
                    result = fn(*args, **kwargs)
            except LockedError as exc:
                audit_log.record(
                    tool=tool_name,
                    arguments=kwargs,
                    caller_pubkey=caller,
                    decision="allowed",
                    result="locked",
                    error=str(exc),
                )
                raise
            except Exception as exc:
                audit_log.record(
                    tool=tool_name,
                    arguments=kwargs,
                    caller_pubkey=caller,
                    decision="allowed",
                    result="error",
                    error=str(exc),
                )
                raise

            if isinstance(result, dict) and result.get("confirmation_required"):
                # A plan was issued, nothing in YunoHost changed - distinct
                # from "success" so the audit trail doesn't imply a write
                # happened when it didn't (PLAN.md Phase 6's confirmation
                # model; policy/enforcement.py's require_confirmation).
                outcome, operation_id = "confirmation_pending", None
            else:
                outcome = "success"
                operation_id = result.get("operation_id") if isinstance(result, dict) else None

            audit_log.record(
                tool=tool_name,
                arguments=kwargs,
                caller_pubkey=caller,
                decision="allowed",
                result=outcome,
                yunohost_operation=operation_id,
            )
            return result

        return wrapper  # type: ignore[return-value]

    return decorator
