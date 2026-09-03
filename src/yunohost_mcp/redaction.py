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
import re
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
        "authorization",
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


_SENSITIVE_KV_PATTERN = re.compile(
    r"\b(?P<key>[\w.-]*(?:" + "|".join(re.escape(m) for m in SENSITIVE_KEY_MARKERS) + r")[\w.-]*)"
    # "Bearer <token>" is a single value split by whitespace (an HTTP
    # Authorization header's own shape) - swallow that leading scheme
    # word too, or only "Bearer" itself would get redacted, leaving the
    # actual token in plain sight right after it.
    r"(?P<sep>\s*[:=]\s*)(?P<value>(?:[Bb]earer\s+)?\S+)",
    re.IGNORECASE,
)
_NSEC_PATTERN = re.compile(r"\bnsec1[a-z0-9]{20,}\b", re.IGNORECASE)


def redact_text(text: str) -> str:
    """Best-effort redaction of secret-*shaped* content inside free text
    (a log line, a shell trace, ...).

    Unlike redact(), which only ever inspects structured dict/list KEY
    names, this scans the text itself for KEY=VALUE / KEY: VALUE pairs
    whose key looks sensitive (SENSITIVE_KEY_MARKERS, same substring
    match as is_sensitive_key) plus bare nsec1... private keys,
    redacting just the value (or the whole key+value for a bare nsec).
    Meant for specific known-freeform fields (operation/service log
    content) that redact()'s key-based pass can never reach - a log
    line's key is "message" or "logs", not "password" - not applied
    universally: scanning arbitrary text for value-shaped patterns risks
    false positives that make a line actively misleading rather than
    merely missing detail, so this stays intentionally narrow (an exact
    KEY=VALUE shape, plus one high-confidence secret format) rather than
    guessing at anything that merely looks sensitive.
    """
    text = _SENSITIVE_KV_PATTERN.sub(lambda m: f"{m['key']}{m['sep']}{REDACTED}", text)
    text = _NSEC_PATTERN.sub(REDACTED, text)
    return text


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
