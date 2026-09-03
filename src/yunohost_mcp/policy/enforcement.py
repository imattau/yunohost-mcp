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
that no confirmation can bypass. When the rule also has
require_owner_signature=True (Phase 13; owner-approval-plan.md's `solo`
profile for v1), a matching but not-yet-approved confirmation_id raises
rather than executing, telling the caller to route it through
approve_operation() (the configured owner, auth/owner.py, Scope.
OWNER_APPROVE) first - the ticket itself is left pending, not consumed, so
this is safe to retry once approved.

@translate_known_errors: converts this module's own known, expected
exceptions (ScopeError, PolicyViolation, a ConfirmationError that escapes
the "issue a new ticket" branch above, plus yunohost/adapter.py's
ToolInputError and YunohostUnavailableError) into
mcp.server.mcpserver.exceptions.ToolError, so a caller/model actually sees
*why* a call was blocked - "'readonly-agent' lacks required scope
'apps.upgrade'", say - instead of the MCP SDK's generic, message-less
"Error executing tool X" it falls back to for any exception type it
doesn't recognize as ToolError/MCPError (see upstream
docs/servers/handling-errors.md: raise anything else and "the model
learns only that the call failed, and your log gets the traceback").
Without this, every one of these expected conditions was indistinguishable
from a genuine server crash to callers, diagnosable only by reading this
server's own systemd journal. Apply it directly alongside
@redact_response (see that decorator's own docstring for why it must stay
immediately under @mcp.tool()) so it sees whatever bubbles up from every
other decorator *and* the tool body itself - including a check called
directly in a tool's own body (e.g. execute_plan re-checking apps.upgrade
policy at execute time) rather than through @require_confirmation's own
`checks=` mechanism.

Deliberately NOT a bare `except ValueError` even though ToolInputError is
one: adapter.py's ToolInputError is raised only for validation this
adapter's own code deliberately performs (a bad catalog source URL, a
missing required ref, ...) - a caller/model could react to the message
and retry. A plain ValueError raised accidentally by unrelated code
(a bug, not a deliberate check) should keep crashing loudly with a
traceback logged, not silently look identical to a deliberate validation
error.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver.exceptions import ToolError

from yunohost_mcp.auth.identity import require_current_request
from yunohost_mcp.auth.owner import OwnerConfigError
from yunohost_mcp.policy.confirmation import ConfirmationError, ConfirmationStore, set_consumed_ticket
from yunohost_mcp.policy.rules import PolicyRule, PolicyViolation
from yunohost_mcp.policy.scopes import Scope
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostUnavailableError

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
                    ticket = confirmation_store.consume(
                        confirmation_id or "",
                        pubkey=request.pubkey,
                        tool=policy_key,
                        arguments=kwargs,
                        require_owner_approval=rule.require_owner_signature,
                    )
                    # Visible to audit/decorator.py's audited_write (the
                    # decorator wrapping this one from the outside) so the
                    # write's own audit entry can record who approved it -
                    # see policy/confirmation.py's _consumed_ticket docstring.
                    set_consumed_ticket(ticket)
                except ConfirmationError:
                    if confirmation_id:
                        raise
                    plan = plan_builder(**kwargs) if plan_builder else {"tool": policy_key, "arguments": kwargs}
                    ticket = confirmation_store.create(
                        pubkey=request.pubkey,
                        tool=policy_key,
                        arguments=kwargs,
                        plan=plan,
                        require_owner_signature=rule.require_owner_signature,
                    )
                    return {
                        "confirmation_required": True,
                        "operation_plan": plan,
                        "confirmation_id": ticket.confirmation_id,
                        "operation_hash": ticket.operation_hash,
                        "expires_at": ticket.expires_at,
                        "owner_signature_required": rule.require_owner_signature,
                    }

            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


_KNOWN_EXPECTED_ERRORS = (
    ScopeError,
    PolicyViolation,
    ConfirmationError,
    OwnerConfigError,
    ToolInputError,
    YunohostUnavailableError,
)


def translate_known_errors(fn: F) -> F:
    """See this module's docstring. Convert ScopeError/PolicyViolation/
    ConfirmationError into ToolError so the caller sees why, not just that,
    a call failed."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except _KNOWN_EXPECTED_ERRORS as exc:
            raise ToolError(str(exc)) from exc

    return wrapper  # type: ignore[return-value]
