"""yunohost-mcp server.

Phase 1: minimal MCP foundation, stdio transport.
Phase 2: adds a Streamable HTTP transport wrapped in NIP-98 authentication
(auth/middleware.py) — proves *who* is calling.
Phase 3: adds identity.toml authorization on top — proves *what* they may
do. A validly-signed request from a pubkey with no identity.toml entry (or
an expired one) is rejected before it ever reaches a tool; a request from a
known identity can only call tools whose required scope its roles grant.
Phase 4: fills out PLAN.md's v0.1 read-only tool list.
Phase 5: adds the first writes (service_restart, backup_create,
app_install, app_upgrade), PLAN.md's "low-risk" set - @require_scope
(authorization) plus @audited_write (a global write lock so at most one
write is ever in flight, plus a JSON-lines audit entry per call -
audit/log.py, policy/locks.py).
Phase 6: adds the safety policy engine and confirmation model
(policy/rules.py, policy/confirmation.py) and the riskier writes that need
them - app_remove, backup_restore, backup_delete, system_upgrade all require a matching
confirm-then-execute round trip; app_upgrade additionally gets hard
policy checks (a recent backup must exist, minimum free space) that no
confirmation can bypass, per PLAN.md's example policy.toml.
Phase 7: adds plan_app_upgrade/execute_plan - dry-run first, execute later,
as two separate calls (PLAN.md's "inspect -> plan -> reason -> execute"
workflow), reusing the same one-shot ticket primitive as Phase 6's
confirmations (policy/confirmation.py's ConfirmationStore) but in its own
namespace (plan_store, not confirmation_store) since a plan_id and a
confirmation_id serve related but distinct purposes.
Phase 8: package-development tools (v0.3) - package_inspect/package_lint
(read-only, packages.read... packages.inspect) and package_install_test/
package_upgrade_test/package_backup_test/package_restore_test/
package_change_url_test/package_remove_test/package_run_tests (writes,
packages.test), all operating on a local path/git URL rather than the app
catalog. Package-test writes require a short-lived source/app-bound session,
confirmation, and owner co-signature because candidate scripts run with
YunoHost privileges.
Phase 9: every tool's response passes through @redact_response
(redaction.py) before it reaches the caller - a second, key-name-matching
layer on top of what YunoHost's own OperationLogger already redacts in its
own logs, applied to the actual returned data itself rather than just log
output. identity.toml also now refuses an nsec (private key) outright
wherever a pubkey is expected - see auth/identity.py's _resolve_key_to_hex.
Phase 10: adds audit_list/audit_get, reading back what @audited_write has
been writing since Phase 5. Gated by Scope.AUDIT_READ, which only the
administrator role grants (policy/roles.py) - "administrator-only" per
PLAN.md, expressed as a scope no other role includes rather than a
role-name check in the tool itself.
Phase 11/12: delegation (auth/delegation.py) lets an identity.toml-mapped
owner grant a disposable agent identity a signed subset of their own
scopes, without sharing a private key - the agent authenticates with its
own NIP-98 signature as always and additionally presents the delegation
event via X-Nostr-Delegation; auth/middleware.py falls back to resolving
it only when the request's own pubkey has no direct identity.toml entry.
Requires this server to have its own Nostr identity (Phase 12, minimal
slice: auth/server_identity.py) so a delegation can name which server it
targets - get_server_identity() lazily generates/loads that keypair only
when something (the server_identity tool, or the http transport) actually
needs it, not merely on import.
Phase 13: owner co-signing for the highest-risk writes (policy/rules.py's
require_owner_signature). A pending confirmation must be
approve_operation()'d by the configured owner (auth/owner.py;
owner-approval-plan.md's `solo` profile for v1 - one owner, resolved from
an explicit setting or, failing that, a single unambiguous administrator
identity) before the original requester can execute it - two independently
NIP-98-signed calls, verified the normal way each already is, bound
together by the confirmation ticket (policy/confirmation.py). The expected
flow has the requester authenticate as an agent's own delegated key
(auth/delegation.py) and the owner approve separately via NIP-46, so their
signer never touches the automated request path. approval_get/
approval_status expose that same pending record - operation_hash included
- read-only, to the confirmation's own requester or the owner, so an
external approval helper can fetch authoritative data before asking the
owner to sign anything, instead of trusting an out-of-band claim. Every
write gated by require_owner_signature also records approved_by in its
own audit entry once executed (audit/decorator.py), not just in the
separate owner.approve entry.
Phase 14: high-level composite workflows (diagnose_app, validate_server,
safe_upgrade, repair_app, test_package) built entirely out of the tools
already in this file - no new yunohost.* call exists anywhere in Phase 14.
They still run through the same @require_scope/@audited_write/policy-check
machinery as the primitives they're built from, per PLAN.md's explicit
"these workflows should still run through the same policy engine".
Phase 15: settings_list/settings_get/settings_set (global YunoHost
settings) and regenconf_pending/regenconf_apply (yunohost.regenconf) -
gap-filled after auditing this tool surface against full YunoHost admin
capability. settings_set/regenconf_apply are gated the same as
firewall_open/close: app-admin and above, confirmation + owner
co-signature (policy/rules.py) - both can change server-wide,
externally-visible behavior (SSO/auth policy, or a service's live config)
in one call. This also prompted moving firewall.write/system.migrate down
from administrator-only to app-admin (policy/roles.py) - owner
co-signature (a *different* identity holding Scope.OWNER_APPROVE, which
stays administrator-only) was already the real per-call safety gate, so
restricting the scope itself to administrator too just made those two
tools unreachable by any agent identity that isn't separately granted
"administrator", not more protected.
Phase 16: domain_dns_suggest/domain_dns_push_preview/domain_dns_push
(yunohost.dns) - the last of the gap-filled tools from the same admin-
capability audit. Reuses DOMAINS_READ/DOMAINS_WRITE rather than new
scopes and requires confirmation plus owner co-signature because registrar
changes are externally visible. Split into a suggest/preview/push trio
(rather than exposing domain_dns_push's own `dry_run` argument) for the
same reason as regenconf_pending/regenconf_apply: a dry-run diff against
the live registrar is a read, and @require_confirmation gates a whole
tool call, not one argument's value.
Phase 17: the remaining smaller items from the same admin-capability
audit - domain_remove, user_permission_info/user_permission_update,
backup_info, and system_reboot/system_shutdown. Two corrections made
along the way after checking upstream source rather than assuming:
permission_create/permission_delete/permission_url (the originally-listed
gap) turned out to be internal-only helpers with no actionsmap entry -
app install/remove's own lifecycle owns permission creation/deletion, so
exposing them directly risked orphaning a permission outside that
lifecycle; user_permission_info/user_permission_update were the real,
actionsmap-exposed gap instead. backup_download similarly turned out to
return a raw Bottle HTTPResponse (static_file(...)) tied to the REST
API's own file-serving path, not JSON-serializable data - backup_info's
own `path` field is the actual answer to "where is this archive," an
admin fetches the bytes over SSH/SCP/SFTP from there. system_reboot/
system_shutdown always pass tools_reboot/tools_shutdown's own `force=True`
(never exposed) since force=False's interactive y/N prompt silently no-ops
under our headless API interface - our own @require_confirmation +
owner-co-signature is the real gate, same pattern as domain_add always
setting ignore_dyndns=True. New Scope.SYSTEM_POWER sits at app-admin, same
as SYSTEM_UPGRADE - not administrator-only, per Phase 15's fix.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import inspect
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from yunohost_mcp.audit.decorator import audited_write
from yunohost_mcp.audit.log import AuditLog
from yunohost_mcp.auth.identity import (
    LOCAL_STDIO_REQUEST,
    get_current_request,
    require_current_request,
    set_current_request,
)
from yunohost_mcp.auth.groups import identity_store_for_settings
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.owner import resolve_owner_pubkey
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.auth.server_identity import ServerIdentity
from yunohost_mcp.config import load_settings
from yunohost_mcp.notify import notify_owner_best_effort, parse_relay_list
from yunohost_mcp.push_approval import request_owner_signature_in_background
from yunohost_mcp.policy.confirmation import ConfirmationError, ConfirmationStore, ConfirmationTicket, SQLiteConfirmationStore
from yunohost_mcp.policy.enforcement import (
    require_confirmation,
    require_scope,
    set_owner_signature_pending_hook,
    translate_known_errors,
)
from yunohost_mcp.policy.locks import WriteLock
from yunohost_mcp.policy.package_sessions import PackageTestSessionError, PackageTestSessionStore, session_path
from yunohost_mcp.policy.rules import (
    PolicyRule,
    PolicyViolation,
    CONTROL_PLANE_APP_ID,
    check_free_space,
    check_recent_backup,
    app_config_policy_key,
    app_change_url_policy_key,
    app_remove_policy_key,
    app_setting_policy_key,
    app_upgrade_policy_key,
    load_policy,
    user_create_policy_key,
    user_group_update_policy_key,
)
from yunohost_mcp.policy.scopes import Scope
from yunohost_mcp.redaction import redact_response
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostAdapter

settings = load_settings()
adapter = YunohostAdapter(settings=settings)
write_lock = WriteLock()
audit_log = AuditLog(path=settings.audit_log_path())
policy_rules = load_policy(settings.policy_file_path())
confirmation_store = (
    SQLiteConfirmationStore(
        settings.confirmation_store_file,
        ttl_seconds=settings.confirmation_ttl_seconds,
        owner_approval_ttl_seconds=settings.owner_approval_ttl_seconds,
    )
    if settings.confirmation_store_file
    else ConfirmationStore(
        ttl_seconds=settings.confirmation_ttl_seconds,
        owner_approval_ttl_seconds=settings.owner_approval_ttl_seconds,
    )
)
plan_store = ConfirmationStore(ttl_seconds=settings.confirmation_ttl_seconds)
catalog_plan_store = ConfirmationStore(ttl_seconds=settings.confirmation_ttl_seconds)
package_test_sessions = PackageTestSessionStore(
    session_path(settings.config_dir), ttl_seconds=settings.package_test_session_ttl_seconds
)
# Shared with create_http_app() below (not just constructed there) so
# get_owner_pubkey() can resolve the bootstrap-administrator fallback
# (auth/owner.py) against the same live-reloaded identity.toml the HTTP
# transport itself authenticates against, on stdio too (LOCAL_STDIO_REQUEST
# never has a real npub, but approve_operation is still reachable there).
identity_store = identity_store_for_settings(settings)


def get_owner_pubkey() -> str | None:
    """Resolve the configured owner (owner-approval-plan.md, v1 `solo`
    profile) fresh on every call - mirrors identity_store's own
    live-reload semantics, so editing identity.toml (or restarting with a
    new YUNOHOST_MCP_OWNER_NPUB) takes effect without a restart, and
    without this module caching a stale answer."""
    return resolve_owner_pubkey(owner_npub=settings.owner_npub, identity_store=identity_store)


def _notify_owner_pending(ticket: ConfirmationTicket) -> None:
    """Wired into policy/enforcement.py's set_owner_signature_pending_hook
    below - owner-approval-plan.md's optional, best-effort NIP-17
    notification (notify.py). A no-op whenever owner_notify_relays is
    unset (the default) or no owner is configured yet; never raises
    (notify_owner_best_effort's own contract) and never affects whether
    the confirmation_required response this fires alongside gets
    returned - it already has been, by the time this runs."""
    relays = parse_relay_list(settings.owner_notify_relays)
    owner_pubkey = get_owner_pubkey()
    if not relays or owner_pubkey is None:
        return
    get_server_identity()  # ensures server_identity_path() exists before reading it below
    notify_owner_best_effort(
        server_secret_key_hex=settings.server_identity_path().read_text().strip(),
        owner_pubkey_hex=owner_pubkey,
        relays=relays,
        confirmation_id=ticket.confirmation_id,
        tool=ticket.tool,
        expires_at=ticket.expires_at,
    )


def _control_plane_audit_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Never persist MCP control-plane values in the audit trail.

    The generic app primitives accept arbitrary strings, and the MCP config
    panel includes bunker URIs containing channel secrets.  Redacting the
    whole value for this app is safer than trying to predict every future
    sensitive panel option.
    """
    if arguments.get("app") != CONTROL_PLANE_APP_ID:
        return arguments
    sanitized = dict(arguments)
    if "value" in sanitized:
        sanitized["value"] = "[REDACTED]"
    return sanitized


def _app_config_plan(app: str, key: str, value: str, **_: Any) -> dict[str, Any]:
    return {
        "action": "set app config",
        "app": app,
        "key": key,
        "value": "[REDACTED]" if app == CONTROL_PLANE_APP_ID else value,
        "warning": (
            "This changes the YunoHost MCP control plane and requires the configured owner's co-signature."
            if app == CONTROL_PLANE_APP_ID
            else "Applies immediately and typically restarts the app's service. "
            "Call app_config_get(app, full=True) first to confirm this is the exact key you mean."
        ),
    }


def _app_setting_plan(
    app: str, key: str, value: str | None = None, delete: bool = False, **_: Any
) -> dict[str, Any]:
    return {
        "action": "delete app setting" if delete else "set app setting",
        "app": app,
        "key": key,
        "value": "[REDACTED]" if app == CONTROL_PLANE_APP_ID else value,
        "warning": (
            "This changes the YunoHost MCP control plane, including potentially its pinned owner identity, "
            "and requires the configured owner's co-signature."
            if app == CONTROL_PLANE_APP_ID
            else "There is no schema behind these keys the way app_config_get(full=True) provides for "
            "config-panel options. Call app_setting_get first to confirm the current value and that this "
            "is the exact key you mean."
        ),
    }


def _push_owner_approval(ticket: ConfirmationTicket) -> None:
    """Wired into the same hook as _notify_owner_pending below -
    push_approval.py's actual live signing request, additive to that
    module's text-only nudge. A no-op (never even spawns the background
    thread) whenever owner_push_approval_enabled is off or no owner is
    configured; push_approval.py itself handles "no session paired yet"
    and every other failure mode as a no-op rather than an error, so this
    never affects whether the confirmation_required response already
    returned to the original caller."""
    if not settings.owner_push_approval_enabled:
        return
    owner_pubkey = get_owner_pubkey()
    if owner_pubkey is None:
        return

    def _mark_approved() -> None:
        # Bypasses the approve_operation MCP tool entirely (push_approval.py
        # has already independently verified the owner's own signature over
        # exactly this ticket - see its _verify_and_extract), which also
        # means its @audited_write wrapper never runs - record the
        # equivalent audit entry by hand so this doesn't silently vanish
        # from the audit trail just because it went through a different path.
        confirmation_store.approve(ticket.confirmation_id, approver_pubkey=owner_pubkey, owner_pubkey=owner_pubkey)
        audit_log.record(
            tool="owner.approve",
            arguments={"confirmation_id": ticket.confirmation_id},
            caller_pubkey=owner_pubkey,
            decision="allowed",
            result="success",
        )

    request_owner_signature_in_background(
        session_path=settings.approve_session_path(),
        owner_pubkey_hex=owner_pubkey,
        tool=ticket.tool,
        operation_plan=ticket.plan,
        operation_hash=ticket.operation_hash,
        confirmation_id=ticket.confirmation_id,
        timeout_seconds=settings.owner_push_approval_timeout_seconds,
        on_approved=_mark_approved,
    )


def _on_owner_signature_pending(ticket: ConfirmationTicket) -> None:
    _notify_owner_pending(ticket)
    _push_owner_approval(ticket)


set_owner_signature_pending_hook(_on_owner_signature_pending)


class AsyncToolMCPServer(MCPServer):
    """Run synchronous tools in asyncio's worker pool.

    The MCP SDK routes sync tools through AnyIO's worker backend. That
    backend can stall indefinitely on some runtimes, leaving tools/call
    requests without a response. YunoHost calls remain off the event loop,
    but use the standard-library executor instead.
    """

    def add_tool(self, fn, **kwargs):
        if not inspect.iscoroutinefunction(fn):
            original = fn

            @functools.wraps(original)
            async def run_in_worker(*args, **call_kwargs):
                # Fake mode is deterministic and non-blocking; keeping it on
                # the event-loop thread also makes in-process protocol tests
                # independent of executor behavior in the host runtime.
                if settings.fake_yunohost:
                    return original(*args, **call_kwargs)
                return await asyncio.to_thread(original, *args, **call_kwargs)

            fn = run_in_worker
        return super().add_tool(fn, **kwargs)


mcp = AsyncToolMCPServer(settings.server_name)

_server_identity: ServerIdentity | None = None


def get_server_identity() -> ServerIdentity:
    """Lazy singleton: only generates/loads the key file (disk I/O, and a
    key generated on first touch) when something actually needs it - the
    server_identity tool, or the http transport's delegation support - not
    merely because this module was imported (stdio users, and every test,
    would otherwise get one written to disk for no reason)."""
    global _server_identity
    if _server_identity is None:
        _server_identity = ServerIdentity.load_or_generate(settings.server_identity_path())
    return _server_identity


def _memory_provenance(tool: str) -> dict[str, str]:
    """Build reserved provenance from the authenticated YunoHost request."""
    request = require_current_request()
    return {
        "_yunohost_source": "yunohost-mcp",
        "_yunohost_server": settings.server_name,
        "_yunohost_tool": tool,
        "_yunohost_caller_pubkey": request.pubkey,
        "_yunohost_request_id": request.event_id,
    }


def _memory_audit_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Keep durable memory content and metadata out of the YunoHost audit log."""
    sanitized: dict[str, Any] = {}
    for key, value in arguments.items():
        if key in {"content", "query"} and isinstance(value, str):
            sanitized[key] = {"length": len(value), "sha256": hashlib.sha256(value.encode()).hexdigest()}
        elif key in {"metadata", "provenance"} and isinstance(value, dict):
            sanitized[key] = {"keys": sorted(str(item) for item in value)}
        else:
            sanitized[key] = value
    return sanitized


def _check_apps_upgrade(rule: PolicyRule) -> None:
    # These reads are brokered in the packaged deployment. Calling them while
    # constructing the confirmation response would forward the same NIP-98
    # envelope to the root helper multiple times; the helper's replay cache
    # correctly rejects that as a replay. The root helper repeats these hard
    # checks immediately before the privileged upgrade, so skipping the
    # frontend copies preserves enforcement without the nested broker calls.
    if settings.broker_socket_path is not None:
        return
    check_free_space(rule, free_bytes=adapter.free_space_bytes())
    check_recent_backup(rule, archive_created_at=adapter.backup_created_at_times(), now=time.time())


def _check_apps_remove(rule: PolicyRule) -> None:
    # See _check_apps_upgrade: the root broker owns the final hard-policy
    # check, and must be the only broker caller for this HTTP request.
    if settings.broker_socket_path is not None:
        return
    check_recent_backup(rule, archive_created_at=adapter.backup_created_at_times(), now=time.time())


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVER_READ)
def server_info() -> dict[str, Any]:
    """Return YunoHost server/component version information."""
    return adapter.server_info()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DIAGNOSIS_READ)
def health_check() -> dict[str, Any]:
    """Return a summary YunoHost diagnosis report."""
    return adapter.health_check()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_READ)
def apps_list(full: bool = False) -> dict[str, Any]:
    """List installed YunoHost apps."""
    return adapter.apps_list(full=full)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_READ)
def memory_get(memory_id: str) -> dict[str, Any]:
    """Return one Polypack memory by exact ID."""
    return adapter.memory_get(memory_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_READ)
def memory_list_contexts() -> dict[str, Any]:
    """List Polypack context namespaces visible to the local store."""
    return adapter.memory_list_contexts()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_READ)
def memory_recall(
    query: str,
    context: str | None = None,
    include_neighbors: bool = False,
    edge_types: list[str] | None = None,
    depth: int = 1,
    neighbor_limit: int = 3,
    limit: int = 20,
    token_budget: int = 4_000,
) -> dict[str, Any]:
    """Recall bounded Polypack memories for an authenticated agent."""
    return adapter.memory_recall(
        query,
        context=context,
        include_neighbors=include_neighbors,
        edge_types=edge_types,
        depth=depth,
        neighbor_limit=neighbor_limit,
        limit=limit,
        token_budget=token_budget,
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_READ)
def memory_context(
    context: str,
    strict_context: bool = False,
    limit: int = 20,
    token_budget: int = 4_000,
) -> dict[str, Any]:
    """Assemble bounded working context from Polypack."""
    return adapter.memory_context(
        context,
        strict_context=strict_context,
        limit=limit,
        token_budget=token_budget,
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_READ)
def memory_thread(start_id: str, max_depth: int = 20) -> dict[str, Any]:
    """Walk a bounded Polypack response/supersession thread."""
    return adapter.memory_thread(start_id, max_depth=max_depth)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_WRITE)
@audited_write(
    "memory.store",
    lock=write_lock,
    audit_log=audit_log,
    argument_sanitizer=_memory_audit_arguments,
)
def memory_store(
    content: str,
    context: str | None = None,
    memory_class: str = "semantic",
    confidence: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store durable Polypack memory with server-authored provenance."""
    return adapter.memory_store(
        content,
        context=context,
        memory_class=memory_class,
        confidence=confidence,
        metadata=metadata,
        provenance=_memory_provenance("memory.store"),
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.MEMORY_FEEDBACK)
@audited_write(
    "memory.feedback",
    lock=write_lock,
    audit_log=audit_log,
    argument_sanitizer=_memory_audit_arguments,
)
def memory_feedback(memory_id: str, useful: bool) -> dict[str, Any]:
    """Record whether a Polypack memory helped this authenticated agent."""
    request = require_current_request()
    return adapter.memory_feedback(memory_id, useful=useful, agent_id=request.pubkey)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_READ)
def app_info(app: str, full: bool = False) -> dict[str, Any]:
    """Return details (manifest, settings, permissions, upgradability) for one installed app."""
    return adapter.app_info(app, full=full)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_READ)
def app_resources(app: str) -> dict[str, Any]:
    """Return the declared YunoHost resources for one installed app."""
    return adapter.app_resources(app)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_CONFIG_READ)
def app_config_get(app: str, key: str = "", full: bool = False, export: bool = False) -> dict[str, Any]:
    """Read an installed app's config-panel settings.

    Call with full=True first to see the panel's schema, labels, and
    current values before calling app_config_set - `key` there must be
    the exact dotted "<panel>.<section>.<option>" id this returns, not a
    label or bare option name. An app with no config panel returns an
    empty config, not an error.
    """
    return adapter.app_config_get(app, key=key, full=full, export=export)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_SETTING_READ)
def app_setting_get(app: str, key: str) -> dict[str, Any]:
    """Read one key from an installed app's settings.yml.

    Narrower and more primitive than app_config_get: this reads whatever
    an app's install/upgrade scripts stashed directly in settings.yml
    (e.g. install_dir, a generated port, a leftover value from a botched
    change_url) - not limited to keys a config_panel.toml declares, which
    most apps don't have at all.
    """
    return adapter.app_setting_get(app, key)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DIAGNOSIS_READ)
def diagnosis_run(categories: list[str] | None = None, force: bool = False) -> dict[str, Any]:
    """Trigger a fresh YunoHost diagnosis run. Can take real time (network/port checks)."""
    return adapter.diagnosis_run(categories=categories, force=force)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DIAGNOSIS_READ)
def diagnosis_get() -> dict[str, Any]:
    """Return the current (cached) aggregated diagnosis report."""
    return adapter.diagnosis_get()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_READ)
def services_list() -> dict[str, Any]:
    """List all YunoHost-managed services and their status."""
    return adapter.services_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_READ)
def service_status(names: list[str]) -> dict[str, Any]:
    """Return status for one or more named services."""
    return adapter.service_status(names)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.LOGS_READ)
def service_logs(
    service: str,
    since: str | None = None,
    until: str | None = None,
    priority: str | None = None,
    grep: str | None = None,
    lines: int = 200,
) -> dict[str, Any]:
    """Structured systemd journal entries for one YunoHost-managed
    service (must be a name services_list() reports) - normalized
    timestamp/service/priority/message per entry.

    `since`/`until` accept journalctl's own syntax ("-1h",
    "2026-09-03 07:00:00", "today", ...). `priority` is a syslog level
    (emerg/alert/crit/err/warning/notice/info/debug, or a range like
    "err..emerg") - e.g. priority="err..emerg" for error-level entries
    only. `grep` filters by a text/regex pattern. `lines` caps how many
    of the most recent matching entries come back (server-enforced
    maximum applies regardless of what's requested). Secret-shaped
    content (a password/token/api_key/... assignment) in each entry's
    message is redacted.
    """
    return adapter.service_logs(service, since=since, until=until, priority=priority, grep=grep, lines=lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.LOGS_READ)
def journal_query(
    units: list[str],
    since: str | None = None,
    until: str | None = None,
    priority: str | None = None,
    grep: str | None = None,
    lines: int = 200,
) -> dict[str, Any]:
    """Query allowlisted system journals, including kernel, OOM, SSH,
    fail2ban, firewall, systemd, and application units."""
    return adapter.journal_query(units, since=since, until=until, priority=priority, grep=grep, lines=lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.LOGS_READ)
def web_logs(
    host: str | None = None,
    path: str | None = None,
    status: int | None = None,
    since: str | None = None,
    until: str | None = None,
    lines: int = 200,
) -> dict[str, Any]:
    """Read bounded, structured Nginx access and error logs."""
    return adapter.web_logs(host=host, path=path, status=status, since=since, until=until, lines=lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVER_READ)
def system_snapshot() -> dict[str, Any]:
    """Return host uptime, boot, resource, process, disk, and OOM evidence."""
    return adapter.system_snapshot()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_READ)
def service_history(names: list[str], lines: int = 50) -> dict[str, Any]:
    """Return service state, exit details, restart counts, and timestamps."""
    return adapter.service_history(names, lines=lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DIAGNOSIS_READ)
def ssh_diagnose(since: str = "-24h", lines: int = 200) -> dict[str, Any]:
    """Collect SSH listener, fail2ban, firewall, service, and auth evidence."""
    return adapter.ssh_diagnose(since=since, lines=lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVER_READ)
def network_snapshot() -> dict[str, Any]:
    """Return local addresses, routes, and listening sockets."""
    return adapter.network_snapshot()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DIAGNOSIS_READ)
def http_probe(url: str, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """Probe an HTTP(S) endpoint and return status, timing, and content type."""
    return adapter.http_probe(url, timeout_seconds=timeout_seconds)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DIAGNOSIS_READ)
def incident_snapshot(
    since: str = "-24h",
    until: str | None = None,
    lines: int = 100,
) -> dict[str, Any]:
    """Collect the main read-only evidence for one incident time window."""
    return adapter.incident_snapshot(since=since, until=until, lines=lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_READ)
def domains_list() -> dict[str, Any]:
    """List domains configured on this YunoHost server."""
    return adapter.domains_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_WRITE)
@audited_write("domains.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "domains.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda domain, install_letsencrypt_cert=False, **_: {
        "action": "add domain",
        "domain": domain,
        "install_letsencrypt_cert": install_letsencrypt_cert,
        "warning": "This is externally visible (DNS/nginx/mail config) and, with "
        "install_letsencrypt_cert=true, contacts Let's Encrypt.",
    },
)
def domain_add(domain: str, install_letsencrypt_cert: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
    """Register a new domain or subdomain on this YunoHost server - a
    prerequisite for app_install's `domain` question, which only accepts
    already-registered domains. Always adds a plain custom domain, never
    subscribes to a new top-level DynDNS domain (nohost.me/noho.st/ynh.fr)
    even if the name would otherwise qualify - a same-host subdomain of
    an already-registered DynDNS domain (e.g. new-app.example.nohost.me)
    is unaffected and works normally.

    A self-signed certificate is always installed immediately.
    install_letsencrypt_cert additionally attempts a real Let's Encrypt
    certificate - this only reliably works for a subdomain of a domain
    that already has a wildcard cert, or a domain whose DNS already
    points here; check the response's `certificate.CA_type` ("letsencrypt"
    vs "selfsigned") rather than assuming success.
    """
    return adapter.domain_add(domain, install_letsencrypt_cert=install_letsencrypt_cert, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_READ)
def domain_cert_info(domain: str) -> dict[str, Any]:
    """Read-only certificate status for an already-registered domain
    (must already appear in domains_list()): CA type/name, remaining
    validity in days, a style/summary badge, whether it's ACME-eligible
    right now, and whether a wildcard covers it - the checks worth doing
    before calling domain_cert_install."""
    return adapter.domain_cert_info(domain)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_WRITE)
@audited_write("domains.cert", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "domains.cert",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda domain, letsencrypt=True, staging=False, **_: {
        "action": "install certificate",
        "domain": domain,
        "requested": "letsencrypt" if letsencrypt else "selfsigned",
        "staging": staging,
        "warning": "Issues/renews the certificate in place on an existing domain "
        "(no remove-and-recreate); with letsencrypt=true this contacts Let's "
        "Encrypt's production endpoint and fails if the domain's DNS/reachability "
        "isn't ACME-ready.",
    },
)
def domain_cert_install(
    domain: str,
    letsencrypt: bool = True,
    staging: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Issue or renew a certificate for an existing domain (must already be
    registered - see domain_add/domains_list) via YunoHost's own
    certificate-install path, not a remove-and-recreate of the domain.

    `letsencrypt=True` (default) requests a real Let's Encrypt certificate;
    `letsencrypt=False` installs a self-signed one instead. `staging` must
    be passed explicitly and must be False - this YunoHost version has no
    ACME staging endpoint configured, so staging=True is rejected rather
    than silently falling back to production.

    Check the response's `certificate.CA_type` ("letsencrypt" vs
    "selfsigned") and `acme_error` rather than assuming success: on ACME
    failure the call still returns normally with the resulting certificate
    status and the underlying error message in `acme_error`, instead of
    raising."""
    return adapter.domain_cert_install(
        domain, letsencrypt=letsencrypt, staging=staging, confirmation_id=confirmation_id
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_READ)
def domain_dns_suggest(domain: str) -> dict[str, Any]:
    """Suggest DNS records for an already-registered domain - basic
    A/AAAA, mail (MX/SPF/DKIM/DMARC), and any extra records YunoHost's
    installed apps contribute - as a formatted zone-file-style block of
    text, the same output `yunohost domain dns suggest` prints. Read-only,
    computed locally from this server's own state; does not contact or
    compare against the domain's actual registrar (see
    domain_dns_push_preview for that). Useful to hand the user something
    to paste at their DNS provider by hand, or to sanity-check before
    domain_dns_push."""
    return adapter.domain_dns_suggest(domain)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_READ)
def domain_dns_push_preview(domain: str, force: bool = False, purge: bool = False) -> dict[str, Any]:
    """Compute what domain_dns_push would actually change on the domain's
    configured DNS registrar - a create/update/delete/unchanged diff
    against the records currently live there - without touching anything.
    Read-only; requires the domain to already have a registrar configured
    (fails clearly if not - see domain_dns_push's docstring). Without
    `force`, the diff only considers records YunoHost itself previously
    created; `force=True` extends that to any matching record regardless
    of origin, matching what domain_dns_push would do with the same flag.
    Always call this before domain_dns_push, especially with
    force=True/purge=True.

    Exception: for a domain whose registrar is YunoHost itself (a
    *.nohost.me/*.noho.st/*.ynh.fr DynDNS domain), upstream YunoHost's own
    domain_dns_push short-circuits to a live (idempotent, harmless) DynDNS
    IP re-registration before it ever reaches its own dry-run check -
    confirmed against a real deployment, not just by reading the source.
    An empty `changes: {}` response for such a domain reflects that
    short-circuit having actually run, not "nothing to do" - there is no
    real preview available for this registrar type."""
    return adapter.domain_dns_push_preview(domain, force=force, purge=purge)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_WRITE)
@audited_write("domains.dns", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "domains.dns",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda domain, force=False, purge=False, **_: {
        "action": "push DNS records to registrar",
        "domain": domain,
        "force": force,
        "purge": purge,
        "warning": "Requires this domain to already have a DNS registrar configured, or fails "
        "cleanly. force=true additionally touches records not created by YunoHost; purge=true "
        "deletes every YunoHost-managed record instead of syncing them - almost always paired "
        "with removing the domain itself, not a normal sync. Externally visible once applied.",
    },
)
def domain_dns_push(
    domain: str,
    force: bool = False,
    purge: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Push domain_dns_suggest's recommended records to the domain's
    configured DNS registrar. Requires a registrar to already be set up
    via the domain's own `dns.registrar` config panel (`app_config_get`/
    `app_config_set` don't cover per-domain config panels - this fails
    with a clear error if none is configured, it does not silently no-op).
    Call domain_dns_push_preview first, always - it shows the exact same
    diff this call would apply, without touching anything. Without
    `force`, only records YunoHost itself previously created are touched;
    `force=True` extends that to any matching record regardless of
    origin. `purge=True` deletes every YunoHost-managed record instead of
    syncing them - almost always combined with removing the domain
    itself, not a normal sync. Requires confirmation and owner co-signature
    because it changes an external registrar, even though it is scoped to
    one domain.

    For a *.nohost.me/*.noho.st/*.ynh.fr domain (registrar is YunoHost
    itself), this performs a live DynDNS IP re-registration instead of
    any create/update/delete against a third-party registrar - the same
    thing YunoHost's own automatic DynDNS refresh already does
    periodically, so harmless, but not the "sync arbitrary DNS records"
    behavior the rest of this docstring describes for an actual
    third-party registrar."""
    return adapter.domain_dns_push(domain, force=force, purge=purge, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.DOMAINS_WRITE)
@audited_write("domains.remove", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "domains.remove",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda domain, remove_apps=False, force=False, **_: {
        "action": "remove domain",
        "domain": domain,
        "remove_apps": remove_apps,
        "warning": "Irreversible: deletes the domain's LDAP entry, certs, and DNS/nginx/mail "
        "config. remove_apps=true additionally removes every app installed on this domain "
        "(each app's own removal, with its own data loss) in the same call - list them first "
        "(apps_list) and confirm that's really intended. Fails cleanly instead if apps remain "
        "installed and remove_apps=false.",
    },
)
def domain_remove(
    domain: str,
    remove_apps: bool = False,
    force: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Remove a registered domain. Refuses to run - and lists the
    offending apps - if any app is still installed on this domain, unless
    `remove_apps=True`, which removes those apps too as part of the same
    call (each one via its own app_remove-equivalent path, with the same
    data loss that implies - check apps_list for this domain first).
    Cannot remove the main domain while any other domain still exists.
    `force` skips YunoHost's own domain-existence assertion (only
    meaningful for cleaning up a domain left in a broken half-added
    state, per domain_add's own `force` semantics - not a way to bypass
    the app-removal check above). Requires confirmation and owner
    co-signature - PLAN.md Phase 13's "domain removal" candidate,
    irreversible either way, even with remove_apps=False."""
    return adapter.domain_remove(domain, remove_apps=remove_apps, force=force, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_READ)
def users_list() -> dict[str, Any]:
    """List YunoHost user accounts."""
    return adapter.users_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    user_create_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda username, domain, password=None, fullname=None, mailbox_quota="0", admin=False, **_: {
        "action": "create user",
        "username": username,
        "domain": domain,
        "fullname": fullname,
        "admin": admin,
        "mailbox_quota": mailbox_quota,
    },
)
def user_create(
    username: str,
    domain: str,
    password: str,
    fullname: str,
    mailbox_quota: str | None = "0",
    admin: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Create a YunoHost user account/mailbox on `domain` (must already be
    registered - see domain_add/domains_list). `admin` adds the new user to
    the `admins` group, granting webadmin/SSH access - grant with care."""
    return adapter.user_create(
        username, domain=domain, password=password, fullname=fullname, mailbox_quota=mailbox_quota, admin=admin,
        confirmation_id=confirmation_id,
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda username, change_password=None, **kwargs: {
        "action": "update user",
        "username": username,
        "changing_password": change_password is not None,
        "fields": sorted(k for k, v in kwargs.items() if v is not None),
    },
)
def user_update(
    username: str,
    mail: str | None = None,
    change_password: str | None = None,
    add_mailforward: list[str] | None = None,
    remove_mailforward: list[str] | None = None,
    add_mailalias: list[str] | None = None,
    remove_mailalias: list[str] | None = None,
    mailbox_quota: str | None = None,
    fullname: str | None = None,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Update an existing YunoHost user's mail/password/quota/fullname.
    Only the fields passed are changed; omitted fields are left as-is."""
    return adapter.user_update(
        username,
        mail=mail,
        change_password=change_password,
        add_mailforward=add_mailforward,
        remove_mailforward=remove_mailforward,
        add_mailalias=add_mailalias,
        remove_mailalias=remove_mailalias,
        mailbox_quota=mailbox_quota,
        fullname=fullname,
        confirmation_id=confirmation_id,
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_DELETE)
@audited_write("users.delete", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.delete",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda username, purge=False, **_: {
        "action": "delete user",
        "username": username,
        "purge": purge,
        "warning": "Irreversible. purge=true also deletes the user's mailbox/home directory.",
    },
)
def user_delete(username: str, purge: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
    """Delete a YunoHost user account. Requires owner co-signature
    (approve_operation) in addition to confirmation - see PLAN.md Phase 13."""
    return adapter.user_delete(username, purge=purge, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_READ)
def user_group_list() -> dict[str, Any]:
    """List YunoHost user groups (e.g. `all_users`, `admins`, and any
    per-app permission groups) and their members."""
    return adapter.user_group_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda groupname, **_: {"action": "create group", "groupname": groupname},
)
def user_group_create(groupname: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Create a new YunoHost user group - a prerequisite for granting a
    custom set of users access to an app permission (see
    user_permission_add) rather than an individual username."""
    return adapter.user_group_create(groupname, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    user_group_update_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda groupname, add=None, remove=None, **_: {
        "action": "update group",
        "groupname": groupname,
        "add": add,
        "remove": remove,
    },
)
def user_group_update(
    groupname: str, add: list[str] | None = None, remove: list[str] | None = None, confirmation_id: str | None = None
) -> dict[str, Any]:
    """Add or remove usernames from a YunoHost group (e.g. adding a user to
    `admins` grants webadmin/SSH access - grant with care)."""
    return adapter.user_group_update(groupname, add=add, remove=remove, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_DELETE)
@audited_write("users.delete", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.delete",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda groupname, **_: {
        "action": "delete group",
        "groupname": groupname,
        "warning": "Irreversible. Any permissions granted to this group are revoked.",
    },
)
def user_group_delete(groupname: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Delete a YunoHost user group. Requires owner co-signature
    (approve_operation) in addition to confirmation - see PLAN.md Phase 13."""
    return adapter.user_group_delete(groupname, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_READ)
def user_permission_list() -> dict[str, Any]:
    """List app/system permissions and which users/groups are allowed each
    one (e.g. which apps a given group can access)."""
    return adapter.user_permission_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.permissions", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.permissions",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda permission, names, **_: {
        "action": "grant permission",
        "permission": permission,
        "names": names,
    },
)
def user_permission_add(permission: str, names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
    """Grant a user or group access to an app permission (e.g. "myapp.main"
    - see user_permission_list for existing permission names). Requires
    owner co-signature (approve_operation) in addition to confirmation -
    see PLAN.md Phase 13's "permission changes" candidate."""
    return adapter.user_permission_add(permission, names, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.permissions", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.permissions",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda permission, names, **_: {
        "action": "revoke permission",
        "permission": permission,
        "names": names,
    },
)
def user_permission_remove(permission: str, names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
    """Revoke a user or group's access to an app permission. Requires owner
    co-signature (approve_operation) in addition to confirmation - see
    PLAN.md Phase 13's "permission changes" candidate."""
    return adapter.user_permission_remove(permission, names, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_READ)
def user_permission_info(permission: str) -> dict[str, Any]:
    """Read one permission's full info (allowed users/groups, label,
    show_tile, protected, URL(s)) - see user_permission_list for known
    permission names. Read-only."""
    return adapter.user_permission_info(permission)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.permissions", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.permissions",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda permission, label=None, show_tile=None, protected=None, **_: {
        "action": "update permission",
        "permission": permission,
        "label": label,
        "show_tile": show_tile,
        "protected": protected,
        "warning": "protected=true bypasses SSO auth entirely for this permission's URL(s) if "
        "set false, or requires it even for otherwise-public apps if set true - double check "
        "which direction is intended before confirming.",
    },
)
def user_permission_update(
    permission: str,
    label: str | None = None,
    show_tile: bool | None = None,
    protected: bool | None = None,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Update a permission's label or dashboard tile visibility
    (`show_tile`) - not who has access, use user_permission_add/
    user_permission_remove for that. Leave an argument None to leave it
    unchanged. `protected` is accepted for backward compatibility but, on
    the currently-installed YunoHost version, raises rather than silently
    doing nothing - the real user_permission_update() has no such
    parameter; protected is only settable via user_permission_add/
    user_permission_remove, alongside a names change. `protected=False`
    on a permission that's meant to require login is a real
    access-control change, not cosmetic - same tier as
    user_permission_add/remove (requires owner co-signature)."""
    return adapter.user_permission_update(
        permission, label=label, show_tile=show_tile, protected=protected, confirmation_id=confirmation_id
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.BACKUPS_READ)
def backups_list() -> dict[str, Any]:
    """List available backup archives."""
    return adapter.backups_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.BACKUPS_READ)
def backup_info(name: str, with_details: bool = False) -> dict[str, Any]:
    """Details for one backup archive - creation time, description, size,
    and its on-disk `path` - and, with `with_details=True`, the apps and
    system parts it actually contains. Read-only. There is no MCP tool to
    fetch the archive's bytes: `path` is where an admin retrieves it from
    (e.g. over SSH/SCP/SFTP) - YunoHost's own backup_download is an
    HTTP-file-serving action tied to its REST API, not something
    meaningfully callable as a plain function."""
    return adapter.backup_info(name, with_details=with_details)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.LOGS_READ)
def operations_list(limit: int | None = None) -> dict[str, Any]:
    """List recent YunoHost operation log entries."""
    return adapter.operations_list(limit=limit)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.LOGS_READ)
def operation_status(name: str) -> dict[str, Any]:
    """Return success/failure status and metadata for one YunoHost operation."""
    return adapter.operation_status(name)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.LOGS_READ)
def operation_logs(name: str, tail_lines: int | None = None) -> dict[str, Any]:
    """Return the log content for one YunoHost operation - most recent
    `tail_lines` lines only (default: a bounded tail, not the whole log;
    pass a larger tail_lines for more). Secret-shaped content (a
    password/token/api_key/... assignment) in the log text is redacted."""
    return adapter.operation_logs(name, tail_lines=tail_lines)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_READ)
def updates_check() -> dict[str, Any]:
    """List apps and system components with pending updates, from cache (no network refresh)."""
    return adapter.updates_check()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_UPDATE)
def updates_refresh(target: str = "apps") -> dict[str, Any]:
    """Refresh cached update metadata over the network: apt-get update
    and/or a re-fetch of every registered app catalog source (including
    a local nostr_catalog feed, if installed), then report what's now
    upgradable. target is "apps", "system", or "all". Can take real time.
    Use this after catalog_publish to confirm a package actually shows up
    in the live catalog - updates_check alone only reads the existing
    cache and won't see a just-published change."""
    return adapter.updates_refresh(target=target)


# Read-only resource mirrors for MCP clients that prefer stable contextual
# resources over tool calls. They intentionally reuse the same scope checks
# and adapter seam as the corresponding tools.
@mcp.resource("yunohost://server")
@redact_response
@require_scope(Scope.SERVER_READ)
def server_resource() -> dict[str, Any]:
    return adapter.server_info()


@mcp.resource("yunohost://diagnosis")
@redact_response
@require_scope(Scope.DIAGNOSIS_READ)
def diagnosis_resource() -> dict[str, Any]:
    return adapter.health_check()


@mcp.resource("yunohost://apps")
@redact_response
@require_scope(Scope.APPS_READ)
def apps_resource() -> dict[str, Any]:
    return adapter.apps_list()


@mcp.resource("yunohost://apps/{app}")
@redact_response
@require_scope(Scope.APPS_READ)
def app_resource(app: str) -> dict[str, Any]:
    return adapter.app_info(app, full=True)


@mcp.resource("yunohost://services")
@redact_response
@require_scope(Scope.SERVICES_READ)
def services_resource() -> dict[str, Any]:
    return adapter.services_list()


@mcp.resource("yunohost://operations")
@redact_response
@require_scope(Scope.LOGS_READ)
def operations_resource() -> dict[str, Any]:
    return adapter.operations_list(limit=50)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_RESTART)
@audited_write("services.restart", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "services.restart",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda names, **_: {
        "action": "restart services",
        "services": names,
        "warning": "Restarting services can interrupt applications and network access.",
    },
)
def service_restart(names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
    """Restart one or more YunoHost services."""
    return adapter.service_restart(names, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_STOP)
@audited_write("services.stop", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "services.stop",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda names, **_: {
        "action": "stop services",
        "services": names,
        "warning": "Unlike restart this is not atomic - the service stays down "
        "until service_start is called.",
    },
)
def service_stop(names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
    """Stop one or more YunoHost services. Call service_start to bring them back up."""
    return adapter.service_stop(names, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_START)
@audited_write("services.start", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "services.start",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
)
def service_start(names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
    """Start one or more stopped YunoHost services."""
    return adapter.service_start(names, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.BACKUPS_CREATE)
@audited_write("backups.create", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "backups.create",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda name=None, description=None, apps=None, system=None, **_: {
        "action": "create backup",
        "name": name,
        "description": description,
        "apps": apps or [],
        "system": system or [],
    },
)
def backup_create(
    name: str | None = None,
    description: str | None = None,
    apps: list[str] | None = None,
    system: list[str] | None = None,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Create a new local backup archive."""
    return adapter.backup_create(
        name=name, description=description, apps=apps, system=system, confirmation_id=confirmation_id
    )


def _validate_backup_archive_name(name: str) -> None:
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ToolInputError("name must be a non-empty string")
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise ToolInputError("name must be an archive name, not a path")


def _backup_delete_plan(name: str) -> dict[str, Any]:
    _validate_backup_archive_name(name)
    return {
        "action": "delete backup archive",
        "name": name,
        "warning": "This permanently deletes the named backup archive and cannot be undone.",
    }


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.BACKUPS_DELETE)
@audited_write("backups.delete", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "backups.delete",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda name, **_: _backup_delete_plan(name),
)
def backup_delete(name: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Permanently delete one local backup archive. Requires owner approval."""
    _validate_backup_archive_name(name)
    return adapter.backup_delete(name, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_INSTALL)
@audited_write("apps.install", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "apps.install",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, label=None, args=None, force=False, **_: {
        "action": "install app",
        "app": app,
        "label": label,
        "force": force,
        "has_custom_args": args is not None,
        "warning": "App installation runs the app's installation scripts with YunoHost privileges.",
    },
)
def app_install(
    app: str, label: str | None = None, args: str | None = None, force: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Install a YunoHost app."""
    return adapter.app_install(app, label=label, args=args, force=force, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.upgrade", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    app_upgrade_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    checks=_check_apps_upgrade,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
)
def app_upgrade(
    app: str | None = None, force: bool = False, url: str | None = None, confirmation_id: str | None = None
) -> dict[str, Any]:
    """Upgrade one installed YunoHost app, or all upgradable apps if none is specified.

    `url` is a Git URL to upgrade from - required for an app that isn't
    in any registered catalog (installed directly via a repo URL rather
    than the catalog), since without it there's no source to diff
    against and this fails with "No apps can be upgraded". Only valid
    together with a single `app`.

    Blocked (PolicyViolation, not confirmable) unless a recent backup
    exists and there is enough free disk space - see policy.toml /
    policy/rules.py's DEFAULT_POLICY["apps.upgrade"].
    """
    return adapter.app_upgrade(app=app, force=force, url=url, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_READ)
def plan_app_upgrade(app: str) -> dict[str, Any]:
    """Report what an upgrade of `app` would involve, without doing it:
    current/target version, and whether apps.upgrade's policy (recent
    backup, free space) would currently block it and why. Pass the
    returned plan_id to execute_plan() to actually upgrade - read-only,
    no lock, no audit entry (nothing in YunoHost changes here).
    """
    facts = adapter.plan_app_upgrade(app)
    rule = policy_rules.get("apps.upgrade", PolicyRule())
    warnings: list[str] = []
    blocked = False
    try:
        _check_apps_upgrade(rule)
    except PolicyViolation as exc:
        warnings.append(str(exc))
        blocked = True

    plan = {**facts, "warnings": warnings, "blocked": blocked}
    ticket = plan_store.create(pubkey=require_current_request().pubkey, tool="plan.app_upgrade", arguments={}, plan=plan)
    return {**plan, "plan_id": ticket.confirmation_id, "expires_at": ticket.expires_at}


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.upgrade", lock=write_lock, audit_log=audit_log)
def execute_plan(plan_id: str) -> dict[str, Any]:
    """Execute a plan previously returned by plan_app_upgrade(). Re-checks
    apps.upgrade's hard policy at execute time, not just at plan time -
    state (free space, backup age) may have drifted in between."""
    request = require_current_request()
    try:
        pending = plan_store.peek(plan_id)
    except ConfirmationError as exc:
        raise ConfirmationError(f"invalid plan_id: {exc}") from exc
    if pending.pubkey == request.pubkey and pending.plan.get("app") == CONTROL_PLANE_APP_ID:
        raise ConfirmationError(
            "planned upgrades of yunohost_mcp must use app_upgrade(), which requires owner co-signature"
        )
    try:
        ticket = plan_store.consume(plan_id, pubkey=request.pubkey, tool="plan.app_upgrade", arguments={})
    except ConfirmationError as exc:
        raise ConfirmationError(f"invalid plan_id: {exc}") from exc

    rule = policy_rules.get("apps.upgrade", PolicyRule())
    _check_apps_upgrade(rule)
    return adapter.app_upgrade(app=ticket.plan["app"])


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_REMOVE)
@audited_write("apps.remove", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    app_remove_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    checks=_check_apps_remove,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, purge=False, **_: {
        "action": "remove app",
        "app": app,
        "purge_data": purge,
        "warning": "This removes the app" + (" and all its data" if purge else "; data may remain unless purge=true")
        + ". This cannot be undone by yunohost-mcp.",
    },
)
def app_remove(app: str, purge: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
    """Remove an installed YunoHost app. Requires confirmation and a recent backup archive."""
    return adapter.app_remove(app, purge=purge, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
# Reuses APPS_UPGRADE rather than a new scope: both roles that can already
# reach for app_remove-and-reinstall as a change_url workaround
# (app-admin, package-developer) already hold APPS_UPGRADE too, so this
# closes that gap for both without a role/identity.toml change.
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.change_url", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    app_change_url_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, domain, path, **_: {
        "action": "change app url",
        "app": app,
        "new_domain": domain,
        "new_path": path,
        "warning": "Requires the app's own change_url script; some apps don't ship one "
        "(app_change_url_no_script) or bake their install path into a built asset that a "
        "plain change_url won't rebuild - check the package before relying on this.",
    },
)
def app_change_url(app: str, domain: str, path: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Move an installed YunoHost app to a new domain and/or path, in place.

    Unlike app_remove + app_install, this preserves the app's data and
    settings - it only reruns the app's own scripts/change_url. Fails
    with app_change_url_no_script if the app doesn't ship one. Some apps'
    change_url script only updates the reverse-proxy config and doesn't
    rebuild app-specific assets that were baked in for the old path - check
    the package (or ask the user) before assuming this alone is sufficient.
    """
    return adapter.app_change_url(app, domain=domain, path=path, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_CONFIG_WRITE)
@audited_write(
    "apps.config", lock=write_lock, audit_log=audit_log, argument_sanitizer=_control_plane_audit_arguments
)
@require_confirmation(
    app_config_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=_app_config_plan,
)
def app_config_set(app: str, key: str, value: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Set one config-panel setting on an installed app. Requires confirmation.

    `key` must be the exact dotted "<panel>.<section>.<option>" id from
    app_config_get(app, full=True) - a panel can reuse the same bare
    option name across sections, so a shortened key can silently target
    the wrong setting. Applying typically restarts the app's service.
    """
    return adapter.app_config_set(app, key=key, value=value, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_SETTING_WRITE)
@audited_write(
    "apps.setting", lock=write_lock, audit_log=audit_log, argument_sanitizer=_control_plane_audit_arguments
)
@require_confirmation(
    app_setting_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=_app_setting_plan,
)
def app_setting_set(
    app: str, key: str, value: str | None = None, delete: bool = False, confirmation_id: str | None = None
) -> dict[str, Any]:
    """Write or delete one key in an installed app's settings.yml. Requires confirmation.

    Exactly one of `value` or `delete=True` must be given.
    """
    return adapter.app_setting_set(app, key, value=value, delete=delete, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.BACKUPS_RESTORE)
@audited_write("backups.restore", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "backups.restore",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda name, apps=None, system=None, force=False, **_: {
        "action": "restore backup",
        "name": name,
        "apps": apps or [],
        "system": system or [],
        "warning": "This overwrites current state with the archive's contents.",
    },
)
def backup_restore(
    name: str,
    apps: list[str] | None = None,
    system: list[str] | None = None,
    force: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Restore from a local backup archive. Requires confirmation."""
    return adapter.backup_restore(name, apps=apps, system=system, force=force, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_UPGRADE)
@audited_write("system.upgrade", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "system.upgrade",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda **_: {
        "action": "upgrade system packages",
        "warning": "This upgrades OS-level packages and may restart services.",
    },
)
def system_upgrade(confirmation_id: str | None = None) -> dict[str, Any]:
    """Upgrade system (OS-level) packages. Requires confirmation."""
    return adapter.system_upgrade(confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_POWER)
@audited_write("system.power", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "system.power",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda **_: {
        "action": "reboot server",
        "warning": "Drops every in-flight connection and operation immediately. The server "
        "comes back up on its own (unlike system_shutdown) once hardware/hypervisor boot "
        "completes - this call itself will not see that happen, the connection is cut first.",
    },
)
def system_reboot(confirmation_id: str | None = None) -> dict[str, Any]:
    """Reboot the host (`systemctl reboot`) immediately once confirmed -
    no further in-process delay or grace period. Requires confirmation and
    owner co-signature, same tier as system_upgrade. Comes back up on its
    own; contrast with system_shutdown, which does not."""
    return adapter.system_reboot(confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_POWER)
@audited_write("system.power", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "system.power",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda **_: {
        "action": "shut down server",
        "warning": "Powers the host off (systemctl poweroff) and does NOT come back up on its "
        "own - unlike system_reboot, this needs someone with physical or remote-power access "
        "to turn it back on. Confirm this is really intended, not a reboot.",
    },
)
def system_shutdown(confirmation_id: str | None = None) -> dict[str, Any]:
    """Power off the host (`systemctl poweroff`) immediately once
    confirmed. Requires confirmation and owner co-signature, same tier as
    system_upgrade. Does NOT come back up on its own - without remote
    power management, someone needs physical access to the machine to
    restore it. Prefer system_reboot unless a real power-off is actually
    what's wanted."""
    return adapter.system_shutdown(confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_UPDATE)
def migrations_list(pending: bool = False, done: bool = False) -> dict[str, Any]:
    """List known migrations. `pending`/`done` filter; the default (neither
    set) returns all of them. Read-only - same scope as updates_check."""
    return adapter.migrations_list(pending=pending, done=done)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_UPDATE)
def migrations_state() -> dict[str, Any]:
    """Return the recorded state (done/pending/skipped) of every migration
    that has ever run on this server. Read-only."""
    return adapter.migrations_state()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SYSTEM_MIGRATE)
@audited_write("system.migrate", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "system.migrate",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda targets=None, skip=False, auto=False, force_rerun=False, **_: {
        "action": "run migrations",
        "targets": targets or [],
        "skip": skip,
        "auto": auto,
        "force_rerun": force_rerun,
        "warning": "Migrations can make irreversible OS/schema-level changes. Read each target's "
        "disclaimer (migrations_list) first - a migration with one is skipped unless "
        "accept_disclaimer=true, and that flag only applies to the first migration in the run.",
    },
)
def migrations_run(
    targets: list[str] | None = None,
    skip: bool = False,
    auto: bool = False,
    force_rerun: bool = False,
    accept_disclaimer: bool = False,
    skip_postmigrations: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Run (or skip, or force-rerun) migrations. Defaults to all pending
    migrations if `targets` is empty. `skip` and `force_rerun` require
    explicit `targets` (never applied to "all pending"). Requires
    confirmation and owner co-signature - same tier as system_upgrade."""
    return adapter.migrations_run(
        targets=targets,
        skip=skip,
        auto=auto,
        force_rerun=force_rerun,
        accept_disclaimer=accept_disclaimer,
        skip_postmigrations=skip_postmigrations,
        confirmation_id=confirmation_id,
    )


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_READ)
def firewall_list(raw: bool = False, protocol: str = "tcp", forwarded: bool = False) -> dict[str, Any]:
    """List firewall rules. `protocol` is "tcp" or "udp" (ignored if `raw`);
    `forwarded` lists UPnP-forwarded ports instead of open ports. Read-only."""
    return adapter.firewall_list(raw=raw, protocol=protocol, forwarded=forwarded)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_READ)
def firewall_is_open(port: int | str, protocol: str) -> dict[str, Any]:
    """Return whether a port is open. `protocol` is "tcp" or "udp". Read-only."""
    return adapter.firewall_is_open(port, protocol)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_WRITE)
@audited_write("firewall.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "firewall.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda port, protocol, comment="", upnp=False, **_: {
        "action": "open firewall port",
        "port": port,
        "protocol": protocol,
        "comment": comment,
        "warning": "Externally visible and reachable once reloaded. Verify this is actually the "
        "port intended - opening the wrong one exposes a service that wasn't meant to be public.",
    },
)
def firewall_open(
    port: int | str,
    protocol: str,
    comment: str = "",
    upnp: bool = False,
    no_reload: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Open a port. `protocol` is "tcp" or "udp"; `port` may be a
    dash-separated range. Requires confirmation and owner co-signature -
    a wrong port/protocol here is externally visible and reachable, same
    risk tier as system_upgrade/backup_restore."""
    return adapter.firewall_open(port, protocol, comment=comment, upnp=upnp, no_reload=no_reload, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_WRITE)
@audited_write("firewall.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "firewall.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda port, protocol, upnp_only=False, **_: {
        "action": "close firewall port",
        "port": port,
        "protocol": protocol,
        "upnp_only": upnp_only,
        "warning": "Closing the wrong port (22/80/443, in particular) can lock the admin out of "
        "this server with no MCP-level undo. Double-check port and protocol before confirming.",
    },
)
def firewall_close(
    port: int | str,
    protocol: str,
    upnp_only: bool = False,
    no_reload: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Close a port. `protocol` is "tcp" or "udp"; `port` may be a
    dash-separated range. Requires confirmation and owner co-signature -
    see the warning in the confirmation plan before approving this on
    port 22/80/443."""
    return adapter.firewall_close(port, protocol, upnp_only=upnp_only, no_reload=no_reload, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_WRITE)
@audited_write("firewall.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "firewall.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda skip_upnp=False, **_: {
        "action": "reload firewall rules",
        "skip_upnp": skip_upnp,
        "warning": "Re-applies the full current rule set immediately - if it was left in an "
        "inconsistent state (e.g. a port closed but not yet reloaded), this is when it takes effect.",
    },
)
def firewall_reload(skip_upnp: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
    """Re-apply the full current firewall rule set. Requires confirmation
    and owner co-signature, same tier as firewall_open/firewall_close -
    this is the point at which any pending rule change actually takes
    effect."""
    return adapter.firewall_reload(skip_upnp=skip_upnp, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SETTINGS_READ)
def settings_list(full: bool = False) -> dict[str, Any]:
    """List YunoHost's global settings (SSO behavior, security toggles,
    misc display options) and their current values. `full` additionally
    returns each setting's type/description/default. Read-only."""
    return adapter.settings_list(full=full)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SETTINGS_READ)
def settings_get(key: str, full: bool = False) -> dict[str, Any]:
    """Read one global setting by key (see settings_list for known keys).
    `full` additionally returns its type/description/default. Read-only."""
    return adapter.settings_get(key, full=full)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SETTINGS_WRITE)
@audited_write("settings.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "settings.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda key, value, **_: {
        "action": "set global setting",
        "key": key,
        "value": value,
        "warning": "Global settings apply server-wide immediately (e.g. SSO behavior, auth "
        "policy) - same risk tier as firewall_open/close.",
    },
)
def settings_set(key: str, value: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Set one global setting (see settings_list for known keys). `value`
    is always passed as a string - YunoHost coerces it to the setting's
    actual type internally. Requires confirmation and owner co-signature,
    same tier as firewall_open/firewall_close."""
    return adapter.settings_set(key, value, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.REGENCONF_READ)
def regenconf_pending(names: list[str] | None = None, with_diff: bool = False) -> dict[str, Any]:
    """List system-service config files (nginx, ssowat, mysql, ...) that
    are out of date versus YunoHost's current internal state, without
    changing anything. `names` restricts the check to specific categories
    (default: all); `with_diff` includes the actual diff text. Read-only -
    call this before regenconf_apply to see what would change."""
    return adapter.regenconf_pending(names=names, with_diff=with_diff)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.REGENCONF_WRITE)
@audited_write("regenconf.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "regenconf.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda names=None, force=False, **_: {
        "action": "apply pending config regeneration",
        "names": names or [],
        "force": force,
        "warning": "Rewrites system-service config files (nginx, ssowat, mysql, ...) in place. "
        "force=true additionally overwrites any file manually edited outside YunoHost - check "
        "regenconf_pending first to see what would change.",
    },
)
def regenconf_apply(
    names: list[str] | None = None,
    force: bool = False,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Regenerate (apply) pending system-service config files. `names`
    restricts this to specific categories (default: all pending); `force`
    additionally overwrites manually-edited files. Requires confirmation
    and owner co-signature, same tier as firewall_open/firewall_close - a
    bad regeneration can lock the admin out the same way a bad firewall
    rule can."""
    return adapter.regenconf_apply(names=names, force=force, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_INSPECT)
def package_inspect(source: str) -> dict[str, Any]:
    """Return the manifest and declared resources for a candidate package.

    `source` is a local path or git URL (not the app catalog) - does not
    install anything.
    """
    return adapter.package_inspect(source)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_INSPECT)
def package_lint(source: str) -> dict[str, Any]:
    """Run the upstream package_linter against a local package path.

    Returns {"unavailable": true} rather than an error if no
    package_linter checkout is configured (YUNOHOST_MCP_PACKAGE_LINTER_PATH)
    - it's optional tooling, not part of yunohost core.
    """
    return adapter.package_lint(source)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_INSPECT)
def package_test_prepare(source: str, app: str | None = None) -> dict[str, Any]:
    """Prepare a short-lived package-test session without changing the host.

    The returned session binds later package-test writes to this exact source,
    app id, and requester identity. ``app`` is required when preparing a test
    against an already-installed app; otherwise it is read from the candidate
    manifest.
    """
    manifest = adapter.package_inspect(source)
    app_id = app or manifest.get("id")
    if not isinstance(app_id, str) or not app_id.strip():
        raise ToolInputError("package manifest did not provide an app id; pass app explicitly")
    session = package_test_sessions.create(pubkey=require_current_request().pubkey, source=source, app_id=app_id)
    return {
        "package_test_id": session.session_id,
        "app": session.app_id,
        "source": session.source,
        "expires_at": session.expires_at,
        "manifest": manifest,
    }


def _package_session(session_id: str, *, source: str | None = None, app: str | None = None):
    if not isinstance(session_id, str) or not session_id:
        raise ToolInputError("session_id is required; call package_test_prepare first")
    try:
        return package_test_sessions.get(
            session_id, pubkey=require_current_request().pubkey, source=source, app_id=app
        )
    except PackageTestSessionError as exc:
        raise ToolInputError(str(exc)) from exc


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test", policy=policy_rules, confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda source, session_id, label=None, args=None, **_: {
        "action": "install candidate package for testing", "source": source,
        "package_test_id": session_id, "label": label, "has_custom_args": args is not None,
        "warning": "Package installation runs candidate scripts with YunoHost privileges and requires owner approval.",
    },
)
def package_install_test(
    source: str, session_id: str, label: str | None = None, args: str | None = None,
    confirmation_id: str | None = None,
) -> dict[str, Any]:
    """Install a candidate package from a local path/git URL, for testing."""
    _package_session(session_id, source=source)
    return adapter.package_install_test(source, label=label, args=args, session_id=session_id, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test", policy=policy_rules, confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, source, session_id, **_: {
        "action": "upgrade test app from candidate package", "app": app, "source": source, "package_test_id": session_id,
        "warning": "Candidate upgrade scripts run with YunoHost privileges and require owner approval.",
    },
)
def package_upgrade_test(app: str, source: str, session_id: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Upgrade an already-installed `app` from a candidate local path/tarball, for testing."""
    _package_session(session_id, source=source, app=app)
    return adapter.package_upgrade_test(app, source, session_id=session_id, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test", policy=policy_rules, confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, session_id, **_: {"action": "backup test app", "app": app, "package_test_id": session_id},
)
def package_backup_test(app: str, session_id: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Create a backup of an installed test app, to verify its backup script works."""
    _package_session(session_id, app=app)
    return adapter.package_backup_test(app, session_id=session_id, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test", policy=policy_rules, confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, archive_name, session_id, **_: {
        "action": "restore test app", "app": app, "archive_name": archive_name, "package_test_id": session_id,
        "warning": "Restoring an archive changes application state and requires owner approval.",
    },
)
def package_restore_test(app: str, archive_name: str, session_id: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Restore a test app from a backup archive, to verify its restore script works."""
    _package_session(session_id, app=app)
    return adapter.package_restore_test(app, archive_name, session_id=session_id, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test", policy=policy_rules, confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, domain, path, session_id, **_: {
        "action": "change test app URL", "app": app, "domain": domain, "path": path, "package_test_id": session_id,
        "warning": "URL changes alter reverse-proxy and app configuration and require owner approval.",
    },
)
def package_change_url_test(app: str, domain: str, path: str, session_id: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Move a test app to a new domain/path, to verify its change_url script works."""
    _package_session(session_id, app=app)
    return adapter.package_change_url_test(app, domain, path, session_id=session_id, confirmation_id=confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test", policy=policy_rules, confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, purge=True, session_id=None, **_: {
        "action": "remove test app", "app": app, "purge": purge, "package_test_id": session_id,
        "warning": "This removes application state and requires owner approval.",
    },
)
def package_remove_test(app: str, session_id: str, purge: bool = True, confirmation_id: str | None = None) -> dict[str, Any]:
    """Remove a test app, to verify its remove script works. Purges data by default."""
    _package_session(session_id, app=app)
    result = adapter.package_remove_test(app, purge=purge, session_id=session_id, confirmation_id=confirmation_id)
    package_test_sessions.delete(session_id, pubkey=require_current_request().pubkey)
    return result


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_INSPECT)
def package_logs(operation: str, tail_lines: int | None = None) -> dict[str, Any]:
    """Return the log for one operation - an alias over operation_logs()
    for the package-development workflow (PLAN.md Phase 8). See that
    tool's docstring for the default tail size and log-text redaction."""
    return adapter.operation_logs(operation, tail_lines=tail_lines)


def _execute_package_test_cycle(source: str, app_id: str | None, confirmation_id: str | None) -> dict[str, Any]:
    manifest = adapter.package_inspect(source)
    resolved_app = app_id or manifest.get("id")
    if not isinstance(resolved_app, str) or not resolved_app:
        raise ToolInputError("package manifest did not provide an app id; pass app_id explicitly")
    session = package_test_sessions.create(
        pubkey=require_current_request().pubkey, source=source, app_id=resolved_app
    )
    try:
        return adapter.package_run_tests(
            source, app_id=resolved_app, confirmation_id=confirmation_id, session_id=session.session_id
        )
    finally:
        package_test_sessions.delete(session.session_id, pubkey=require_current_request().pubkey)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda source, app_id=None, **_: {
        "action": "run package install/backup/remove/restore test cycle",
        "source": source,
        "app_id": app_id,
        "warning": "This installs and removes the candidate app and creates a test backup on the server.",
    },
)
def package_run_tests(
    source: str, app_id: str | None = None, confirmation_id: str | None = None
) -> dict[str, Any]:
    """Run the standard install -> backup -> remove -> restore -> remove
    cycle against a candidate package in one call. Stops at the first
    failing step; see yunohost/adapter.py's package_run_tests for exactly
    what each step does and why this isn't package_check's full CI matrix.
    """
    return _execute_package_test_cycle(source, app_id, confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.AUDIT_READ)
@require_confirmation(
    "audit.read",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    plan_builder=lambda limit=None, **_: {
        "action": "read audit trail",
        "limit": limit,
        "warning": "The audit trail includes every identity's tool calls, not just yours.",
    },
)
def audit_list(limit: int | None = None, confirmation_id: str | None = None) -> dict[str, Any]:
    """List audit trail entries, newest first. Requires Scope.AUDIT_READ
    (app-admin and above) plus owner co-signature per call - see
    audit_get."""
    return {"entries": audit_log.list(limit=limit)}


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.AUDIT_READ)
@require_confirmation(
    "audit.read",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    plan_builder=lambda audit_id, **_: {
        "action": "read audit trail entry",
        "audit_id": audit_id,
        "warning": "The audit trail includes every identity's tool calls, not just yours.",
    },
)
def audit_get(audit_id: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Return one audit trail entry by id. Requires Scope.AUDIT_READ
    (app-admin and above) plus owner co-signature per call: unlike other
    confirmed reads, this isn't gated for the caller's own protection -
    it's gated because the trail exposes every *other* identity's calls
    too, so the owner approves each read rather than it being a standing
    grant."""
    entry = audit_log.get(audit_id)
    if entry is None:
        raise ToolInputError(f"no audit entry with id {audit_id!r}")
    return entry


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.OWNER_APPROVE)
@audited_write("owner.approve", lock=write_lock, audit_log=audit_log)
def approve_operation(confirmation_id: str) -> dict[str, Any]:
    """Owner co-signature (PLAN.md Phase 13; owner-approval-plan.md's
    `solo` profile for v1) for a pending high-risk operation (system.
    upgrade, backups.restore - see policy/rules.py's
    require_owner_signature). Marks the confirmation approved so its
    original requester can then execute it by calling the same tool again
    with this confirmation_id - approving does not execute anything itself.

    The approver must be the one configured owner (auth/owner.py) - not
    just any identity with Scope.OWNER_APPROVE (still required as a
    baseline gate below). The expected flow: the original request comes
    from an agent's own delegated key, and the owner approves with their
    own npub through an external NIP-46 signer.
    """
    request = require_current_request()
    if request.delegation is not None:
        # A delegated identity is by construction an agent acting on
        # authority someone else granted it (auth/delegation.py) - never
        # the owner in person, regardless of what pubkey/scopes it
        # resolves to. Without this check, an owner_npub or bootstrap
        # "administrator" misconfigured to coincide with an agent's own
        # key (the exact thing policy/roles.py's _APP_ADMIN comment says
        # should never happen in practice) would let that agent's own
        # delegated call satisfy approver_pubkey == owner_pubkey below -
        # i.e. an agent approving its own request. The legitimate v1 flow
        # this must not break - a human owner calling a protected tool
        # directly and then self-approving (confirmation.py's own
        # docstring) - never carries an X-Nostr-Delegation header, so it's
        # unaffected.
        raise ConfirmationError(
            "owner co-signature must come from the owner's own key directly, not a delegated identity"
        )
    owner_pubkey = get_owner_pubkey()
    if owner_pubkey is None:
        raise ConfirmationError(
            "no owner is configured for this server - set an explicit owner (admin_npub) or "
            "ensure exactly one administrator identity exists before approving high-risk operations"
        )
    try:
        ticket = confirmation_store.approve(
            confirmation_id, approver_pubkey=request.pubkey, owner_pubkey=owner_pubkey
        )
    except ConfirmationError as exc:
        raise ConfirmationError(f"cannot approve: {exc}") from exc
    return {
        "approved": True,
        "confirmation_id": ticket.confirmation_id,
        "tool": ticket.tool,
        "operation_plan": ticket.plan,
        "operation_hash": ticket.operation_hash,
        "approved_by": request.pubkey,
    }


def _visible_confirmation(confirmation_id: str) -> ConfirmationTicket:
    """Shared access rule for approval_get/approval_status
    (owner-approval-plan.md): visible to the confirmation's own requester
    (so an agent can poll what it's waiting on) and to Scope.OWNER_APPROVE
    holders (the owner, or their NIP-46 approval helper acting under the
    owner's own identity) - no one else. Uses peek(), not consume(): a
    read tool must never advance or invalidate ticket state."""
    request = require_current_request()
    ticket = confirmation_store.peek(confirmation_id)
    if ticket.pubkey != request.pubkey and not request.has_scope(Scope.OWNER_APPROVE):
        raise ConfirmationError("not authorized to view this confirmation")
    return ticket


@mcp.tool()
@redact_response
@translate_known_errors
def approval_get(confirmation_id: str) -> dict[str, Any]:
    """Authoritative record for a pending confirmation (owner-approval-plan.md).

    The external NIP-46 approval helper calls this before asking the owner
    to sign anything, so it reviews server-computed data - operation_hash
    included - rather than trusting whatever the requester claims out of
    band. Any argument, target, or operation_hash mismatch between what
    the helper displays and what it's about to sign should be treated as
    an invalidated approval.
    """
    ticket = _visible_confirmation(confirmation_id)
    return {
        "confirmation_id": ticket.confirmation_id,
        "tool": ticket.tool,
        "operation_plan": ticket.plan,
        "operation_hash": ticket.operation_hash,
        "requester_pubkey": ticket.pubkey,
        "created_at": ticket.created_at,
        "expires_at": ticket.expires_at,
        "approved": ticket.owner_approved_by is not None,
        "approved_by": ticket.owner_approved_by,
    }


@mcp.tool()
@redact_response
@translate_known_errors
def approval_status(confirmation_id: str) -> dict[str, Any]:
    """Lightweight poll for whether a pending confirmation
    (owner-approval-plan.md) has been owner-approved yet - the same access
    rule as approval_get, without the full operation plan, for a requester
    that just wants to know whether to retry the original call yet.

    Call this in a loop yourself after a require_owner_signature call
    returns confirmation_required (see that response's own "next_step") -
    push_approval.py may resolve it within seconds via the owner's paired
    signer, with no human needing to report back that it happened. Poll
    at a reasonable interval (a few seconds, not a tight loop) until
    approved is true or expires_at passes, then retry the original call
    with this confirmation_id."""
    ticket = _visible_confirmation(confirmation_id)
    return {
        "confirmation_id": ticket.confirmation_id,
        "approved": ticket.owner_approved_by is not None,
        "expires_at": ticket.expires_at,
    }


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_READ)
def diagnose_app(app: str) -> dict[str, Any]:
    """One-call app diagnostic: app info, the server's current diagnosis,
    and recent operation log entries mentioning this app. Read-only."""
    return adapter.diagnose_app(app)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVER_READ)
def validate_server() -> dict[str, Any]:
    """A broad server health snapshot in one call: version info, diagnosis,
    pending updates, service status, and backup archives. Read-only."""
    return adapter.validate_server()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.upgrade", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    app_upgrade_policy_key,
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda app, **_: {
        "action": "safely upgrade app",
        "app": app,
        "warning": "This upgrades the YunoHost MCP control plane and requires the configured owner's co-signature."
        if app == CONTROL_PLANE_APP_ID
        else "This creates a safety backup, upgrades the app, and runs post-upgrade health checks.",
    },
)
def safe_upgrade(app: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """PLAN.md Phase 14's flagship workflow: diagnosis -> inspect app ->
    create a fresh safety backup -> upgrade -> check app/HTTP endpoint ->
    re-diagnose -> one report. Runs through apps.upgrade's own policy: free
    space is checked up front (nothing in this workflow can create disk
    space), and the backup requirement is re-verified after this workflow's
    own backup step actually happens, not just assumed to have worked.
    """
    rule = policy_rules.get(app_upgrade_policy_key(app=app), PolicyRule())
    check_free_space(rule, free_bytes=adapter.free_space_bytes())
    result = adapter.safe_upgrade(app, confirmation_id=confirmation_id)
    check_recent_backup(rule, archive_created_at=adapter.backup_created_at_times(), now=time.time())
    return result


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.SERVICES_RESTART)
@audited_write("services.restart", lock=write_lock, audit_log=audit_log)
def repair_app(app: str, strategy: str = "conservative") -> dict[str, Any]:
    """Diagnose an app and attempt bounded remediation. Only "conservative"
    is implemented: restart services whose name contains this app id, then
    re-diagnose - no reinstall, upgrade, or forced removal regardless of
    findings.
    """
    return adapter.repair_app(app, strategy=strategy)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "packages.test",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda source, app_id=None, **_: {
        "action": "run package install/backup/remove/restore test cycle",
        "source": source,
        "app_id": app_id,
        "warning": "This installs and removes the candidate app and creates a test backup on the server.",
    },
)
def test_package(
    source: str, app_id: str | None = None, confirmation_id: str | None = None
) -> dict[str, Any]:
    """Alias for package_run_tests() - PLAN.md Phase 14 names this
    separately from Phase 8's package_run_tests, but it's the same
    install -> backup -> remove -> restore cycle; see
    yunohost/adapter.py's package_run_tests for what each step does.
    """
    return _execute_package_test_cycle(source, app_id, confirmation_id)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.CATALOG_INSPECT)
def catalog_package_inspect(source: str, ref: str | None = None) -> dict[str, Any]:
    """Inspect a local or remote YunoHost package for catalogue publication."""
    return adapter.catalog_package_inspect(source, ref=ref)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.CATALOG_INSPECT)
def catalog_publish_plan(source: str, ref: str | None = None) -> dict[str, Any]:
    """Build a signed catalogue declaration without contacting any relay."""
    plan = adapter.catalog_publish_plan(source, ref=ref)
    ticket = catalog_plan_store.create(
        pubkey=require_current_request().pubkey,
        tool="catalog.publish",
        arguments={"source": source, "ref": ref},
        plan=plan,
    )
    return {**plan, "plan_id": ticket.confirmation_id, "expires_at": ticket.expires_at}


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.CATALOG_VERIFY)
def catalog_verify(event_or_naddr: str) -> dict[str, Any]:
    """Verify a signed declaration event or fetch and verify an naddr."""
    return adapter.catalog_verify(event_or_naddr)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.CATALOG_INSPECT)
def catalog_list() -> dict[str, Any]:
    """List every app currently declared in the Nostr catalogue - not just
    what's installed on this server. Queries the configured relays fresh
    on every call (no local cache), applying the same trusted-publisher
    policy nostr-catalogd itself uses when more than one publisher has
    declared the same app id."""
    return adapter.catalog_list()


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.CATALOG_PUBLISH)
@audited_write("catalog.publish", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "catalog.publish",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    defer_to_broker=lambda: settings.broker_socket_path is not None,
    plan_builder=lambda plan_id, **_: {
        "action": "publish YunoHost package declaration to configured Nostr relays",
        "plan_id": plan_id,
        "warning": "This publishes externally visible catalogue metadata.",
    },
)
def catalog_publish(plan_id: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Publish an existing catalogue plan after administrator confirmation."""
    request = require_current_request()
    try:
        pending = catalog_plan_store.peek(plan_id)
        arguments = {"source": pending.plan.get("source"), "ref": pending.plan.get("ref")}
        plan_ticket = catalog_plan_store.consume(
            plan_id,
            pubkey=request.pubkey,
            tool="catalog.publish",
            arguments=arguments,
        )
    except (ConfirmationError, KeyError) as exc:
        raise ConfirmationError(f"invalid catalog plan_id: {exc}") from exc
    return adapter.catalog_publish(
        source=plan_ticket.plan["source"],
        ref=plan_ticket.plan.get("ref"),
        confirmation_id=confirmation_id,
        plan_id=plan_id,
    )


@mcp.tool()
@redact_response
@translate_known_errors
def whoami() -> dict[str, Any]:
    """Return the caller's resolved Nostr identity: pubkey, name, roles, and scopes.

    Requires no scope of its own — any authenticated, identity.toml-mapped
    caller may ask who they are, even one whose roles grant nothing else.
    Only meaningful over the HTTP transport; over stdio there is no NIP-98
    handshake, so this returns unauthenticated.
    """
    request = get_current_request()
    if request is None or request.identity is None:
        return {"authenticated": False, "pubkey": None}
    return {
        "authenticated": True,
        "pubkey": request.pubkey,
        "name": request.identity.name,
        "roles": list(request.identity.roles),
        "scopes": sorted(s.value for s in request.scopes),
    }


@mcp.tool()
@redact_response
@translate_known_errors
def server_identity() -> dict[str, Any]:
    """Return this server's own Nostr identity (Phase 12): its npub and hex
    pubkey. A delegation (Phase 11) must name this exact pubkey in its
    'server' tag to be accepted here. No scope required - this is public
    information a caller needs *before* it can construct a valid delegation
    naming this server, not something to gate behind auth for this server.
    """
    identity = get_server_identity()
    return {"npub": identity.npub, "pubkey": identity.pubkey_hex}


def create_http_app():
    """Build the ASGI app for the Streamable HTTP transport: MCP wrapped in NIP-98 auth + authz.

    identity.toml/revoked_delegations.toml use the `.live()` stores, not
    `.load()`: both files are meant to be edited by an admin while the
    server keeps running (granting an identity, revoking a delegation), and
    a one-time snapshot taken here at startup would silently require a
    full service restart for either to take effect.
    """
    # streamable_http_app()'s own DNS-rebinding Host check defaults to
    # localhost-only (mcp SDK), which rejects every request once nginx
    # forwards the real public Host header via proxy_set_header Host $host.
    # NostrAuthMiddleware below already requires a validly signed NIP-98
    # event - bound to the exact request URL - on every call, which is what
    # DNS-rebinding protection exists to approximate for unauthenticated
    # dev servers, so it's redundant (and actively broken) here.
    inner_app = mcp.streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )
    return NostrAuthMiddleware(
        inner_app,
        identity_store=identity_store,
        replay_cache=ReplayCache(ttl_seconds=settings.nip98_replay_ttl_seconds),
        clock_skew_seconds=settings.nip98_clock_skew_seconds,
        server_identity=get_server_identity(),
        revocation_store=RevocationStore.live(settings.revoked_delegations_path()),
        max_request_body_bytes=settings.max_request_body_bytes,
        request_timeout_seconds=settings.request_timeout_seconds,
        max_concurrent_requests=settings.max_concurrent_requests,
        public_base_url=settings.public_base_url,
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog=settings.server_name)
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="stdio for local MCP clients, http for NIP-98-authenticated remote access",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if args.transport == "stdio":
        # No NIP-98 handshake applies to stdio: whoever can run this process
        # locally already has the access level a `yunohost` CLI invocation
        # would. See auth/identity.py's LOCAL_STDIO_REQUEST for why this is
        # an explicit grant here rather than an implicit fallback.
        set_current_request(LOCAL_STDIO_REQUEST)
        mcp.run()
        return

    import uvicorn

    uvicorn.run(create_http_app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
