"""Scope enforcement for MCP tool handlers.

Tool handlers declare the one scope they need with @require_scope(...); the
decorator reads the current request's resolved identity (set by
NostrAuthMiddleware after authentication + identity.toml lookup) and raises
if that identity's scopes don't include it. Handlers should never check
`request.identity.roles` directly — scopes are the only thing that should
ever gate a tool, per PLAN.md Phase 3.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TypeVar

from yunohost_mcp.auth.identity import require_current_request
from yunohost_mcp.policy.scopes import Scope

F = TypeVar("F", bound=Callable)


class ScopeError(PermissionError):
    """The current identity does not have the scope a tool requires."""


def require_scope(scope: Scope) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            request = require_current_request()
            if not request.has_scope(scope):
                who = request.identity.name if request.identity else request.pubkey
                raise ScopeError(f"{who!r} lacks required scope {scope.value!r}")
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
