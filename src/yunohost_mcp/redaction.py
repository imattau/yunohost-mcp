"""Central secret redaction (PLAN.md Phase 9).

One redaction pass, reused everywhere caller-visible data could carry a
secret through: every MCP tool's response (`@redact_response`, applied to
every tool in server.py) and the audit trail (audit/log.py). This is a
second, blunt, key-name-matching layer on top of what YunoHost's own
OperationLogger already redacts (DB passwords - see
PHASE0_INVESTIGATION.md) - not a replacement for it, and it will not catch
a secret embedded in a free-text field under an innocuous key name (a
`description` field containing a pasted API key, say). Matching is
substring, not exact, and deliberately broad: a false-positive redaction
(a field named "password_policy" losing its value) is a much smaller
problem than a missed one.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

SENSITIVE_KEY_MARKERS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "private_key",
        "privkey",
        "nsec",
        "api_key",
        "apikey",
        "session",
        "cookie",
    }
)

REDACTED = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    key_lower = key.lower()
    return any(marker in key_lower for marker in SENSITIVE_KEY_MARKERS)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if is_sensitive_key(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


F = TypeVar("F", bound=Callable[..., Any])


def redact_response(fn: F) -> F:
    """Redact a tool's return value before it goes back to the MCP client.

    Apply directly under @mcp.tool() (i.e. run last, on the truly final
    result) so every other decorator - @require_scope, @audited_write,
    @require_confirmation - still sees the raw value for its own purposes
    (audited_write's own argument redaction is separate and unaffected;
    it logs arguments, not this decorator's return value).
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        result = fn(*args, **kwargs)
        return redact(result) if isinstance(result, (dict, list)) else result

    return wrapper  # type: ignore[return-value]
