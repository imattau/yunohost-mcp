"""Scope + policy enforcement for MCP tool handlers.

@require_scope(...): the caller's identity (set by NostrAuthMiddleware
after authentication + identity.toml lookup) must include this scope, or
the call is denied (PLAN.md Phase 3). Handlers should never check
`request.identity.roles` directly - scopes are the only thing that should
ever gate a tool.

@require_confirmation(...): PLAN.md Phase 6's confirmation model. If the
resolved PolicyRule for `policy_key` has require_confirmation=True, a call
without a matching confirmation_id short-circuits into a
confirmation_required response (plan + confirmation_id + expiry) instead of
executing; a call presenting a valid, matching confirmation_id proceeds. A
call presenting an *invalid* one raises rather than silently issuing a new
ticket, so a caller finds out why immediately. `checks`, if given, runs on
every call (both the "show me the plan" and the confirmed call) and raises
PolicyViolation for hard requirements (require_backup, minimum_free_space)
that no confirmation can bypass.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from yunohost_mcp.auth.identity import require_current_request
from yunohost_mcp.policy.confirmation import ConfirmationError, ConfirmationStore
from yunohost_mcp.policy.rules import PolicyRule
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


def require_confirmation(
    policy_key: str,
    *,
    policy: dict[str, PolicyRule],
    confirmation_store: ConfirmationStore,
    plan_builder: Callable[..., dict[str, Any]] | None = None,
    checks: Callable[[PolicyRule], None] | None = None,
) -> Callable[[F], F]:
    """`plan_builder` may be omitted when `policy[policy_key]` never has
    require_confirmation=True (e.g. a rule used only for its hard `checks`,
    like apps.upgrade's require_backup/minimum_free_space) - it's only
    called if a confirmation is actually about to be issued."""
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            confirmation_id = kwargs.pop("confirmation_id", None)
            request = require_current_request()
            rule = policy.get(policy_key, PolicyRule())

            if checks is not None:
                checks(rule)  # PolicyViolation here is never confirmable away

            if rule.require_confirmation:
                try:
                    confirmation_store.consume(
                        confirmation_id or "", pubkey=request.pubkey, tool=policy_key, arguments=kwargs
                    )
                except ConfirmationError:
                    if confirmation_id:
                        raise
                    plan = plan_builder(**kwargs) if plan_builder else {"tool": policy_key, "arguments": kwargs}
                    ticket = confirmation_store.create(
                        pubkey=request.pubkey, tool=policy_key, arguments=kwargs, plan=plan
                    )
                    return {
                        "confirmation_required": True,
                        "operation_plan": plan,
                        "confirmation_id": ticket.confirmation_id,
                        "expires_at": ticket.expires_at,
                    }

            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
