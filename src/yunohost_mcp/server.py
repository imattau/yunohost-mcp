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
them - app_remove, backup_restore, system_upgrade all require a matching
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
catalog. No confirmation step: this scope exists specifically for a fast
dev-iteration loop, so friction is scope (who may call these at all, i.e.
the package-developer role) rather than a per-call confirmation - see
yunohost/adapter.py's Phase 8 section for why.
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
"""

from __future__ import annotations

import argparse
import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from yunohost_mcp.audit.decorator import audited_write
from yunohost_mcp.audit.log import AuditLog
from yunohost_mcp.auth.identity import (
    LOCAL_STDIO_REQUEST,
    IdentityStore,
    get_current_request,
    require_current_request,
    set_current_request,
)
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.auth.server_identity import ServerIdentity
from yunohost_mcp.config import load_settings
from yunohost_mcp.policy.confirmation import ConfirmationError, ConfirmationStore
from yunohost_mcp.policy.enforcement import require_confirmation, require_scope
from yunohost_mcp.policy.locks import WriteLock
from yunohost_mcp.policy.rules import PolicyRule, PolicyViolation, check_free_space, check_recent_backup, load_policy
from yunohost_mcp.policy.scopes import Scope
from yunohost_mcp.redaction import redact_response
from yunohost_mcp.yunohost.adapter import YunohostAdapter

settings = load_settings()
adapter = YunohostAdapter(settings=settings)
write_lock = WriteLock()
audit_log = AuditLog(path=settings.audit_log_path())
policy_rules = load_policy(settings.policy_file_path())
confirmation_store = ConfirmationStore(ttl_seconds=settings.confirmation_ttl_seconds)
plan_store = ConfirmationStore(ttl_seconds=settings.confirmation_ttl_seconds)

mcp = MCPServer(settings.server_name)

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


def _check_apps_upgrade(rule: PolicyRule) -> None:
    check_free_space(rule)
    check_recent_backup(rule, archives=adapter.backups_list().get("archives", []), now=time.time())


def _check_apps_remove(rule: PolicyRule) -> None:
    check_recent_backup(rule, archives=adapter.backups_list().get("archives", []), now=time.time())


@mcp.tool()
@redact_response
@require_scope(Scope.SERVER_READ)
def server_info() -> dict[str, Any]:
    """Return YunoHost server/component version information."""
    return adapter.server_info()


@mcp.tool()
@redact_response
@require_scope(Scope.DIAGNOSIS_READ)
def health_check() -> dict[str, Any]:
    """Return a summary YunoHost diagnosis report."""
    return adapter.health_check()


@mcp.tool()
@redact_response
@require_scope(Scope.APPS_READ)
def apps_list(full: bool = False) -> dict[str, Any]:
    """List installed YunoHost apps."""
    return adapter.apps_list(full=full)


@mcp.tool()
@redact_response
@require_scope(Scope.APPS_READ)
def app_info(app: str, full: bool = False) -> dict[str, Any]:
    """Return details (manifest, settings, permissions, upgradability) for one installed app."""
    return adapter.app_info(app, full=full)


@mcp.tool()
@redact_response
@require_scope(Scope.DIAGNOSIS_READ)
def diagnosis_run(categories: list[str] | None = None, force: bool = False) -> dict[str, Any]:
    """Trigger a fresh YunoHost diagnosis run. Can take real time (network/port checks)."""
    return adapter.diagnosis_run(categories=categories, force=force)


@mcp.tool()
@redact_response
@require_scope(Scope.DIAGNOSIS_READ)
def diagnosis_get() -> dict[str, Any]:
    """Return the current (cached) aggregated diagnosis report."""
    return adapter.diagnosis_get()


@mcp.tool()
@redact_response
@require_scope(Scope.SERVICES_READ)
def services_list() -> dict[str, Any]:
    """List all YunoHost-managed services and their status."""
    return adapter.services_list()


@mcp.tool()
@redact_response
@require_scope(Scope.SERVICES_READ)
def service_status(names: list[str]) -> dict[str, Any]:
    """Return status for one or more named services."""
    return adapter.service_status(names)


@mcp.tool()
@redact_response
@require_scope(Scope.DOMAINS_READ)
def domains_list() -> dict[str, Any]:
    """List domains configured on this YunoHost server."""
    return adapter.domains_list()


@mcp.tool()
@redact_response
@require_scope(Scope.USERS_READ)
def users_list() -> dict[str, Any]:
    """List YunoHost user accounts."""
    return adapter.users_list()


@mcp.tool()
@redact_response
@require_scope(Scope.BACKUPS_READ)
def backups_list() -> dict[str, Any]:
    """List available backup archives."""
    return adapter.backups_list()


@mcp.tool()
@redact_response
@require_scope(Scope.LOGS_READ)
def operations_list(limit: int | None = None) -> dict[str, Any]:
    """List recent YunoHost operation log entries."""
    return adapter.operations_list(limit=limit)


@mcp.tool()
@redact_response
@require_scope(Scope.LOGS_READ)
def operation_status(name: str) -> dict[str, Any]:
    """Return success/failure status and metadata for one YunoHost operation."""
    return adapter.operation_status(name)


@mcp.tool()
@redact_response
@require_scope(Scope.LOGS_READ)
def operation_logs(name: str) -> dict[str, Any]:
    """Return the full log content for one YunoHost operation."""
    return adapter.operation_logs(name)


@mcp.tool()
@redact_response
@require_scope(Scope.APPS_READ)
def updates_check() -> dict[str, Any]:
    """List apps and system components with pending updates, from cache (no network refresh)."""
    return adapter.updates_check()


@mcp.tool()
@redact_response
@require_scope(Scope.SERVICES_RESTART)
@audited_write("services.restart", lock=write_lock, audit_log=audit_log)
def service_restart(names: list[str]) -> dict[str, Any]:
    """Restart one or more YunoHost services."""
    return adapter.service_restart(names)


@mcp.tool()
@redact_response
@require_scope(Scope.BACKUPS_CREATE)
@audited_write("backups.create", lock=write_lock, audit_log=audit_log)
def backup_create(
    name: str | None = None,
    description: str | None = None,
    apps: list[str] | None = None,
    system: list[str] | None = None,
) -> dict[str, Any]:
    """Create a new local backup archive."""
    return adapter.backup_create(name=name, description=description, apps=apps, system=system)


@mcp.tool()
@redact_response
@require_scope(Scope.APPS_INSTALL)
@audited_write("apps.install", lock=write_lock, audit_log=audit_log)
def app_install(app: str, label: str | None = None, args: str | None = None, force: bool = False) -> dict[str, Any]:
    """Install a YunoHost app."""
    return adapter.app_install(app, label=label, args=args, force=force)


@mcp.tool()
@redact_response
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.upgrade", lock=write_lock, audit_log=audit_log)
@require_confirmation("apps.upgrade", policy=policy_rules, confirmation_store=confirmation_store, checks=_check_apps_upgrade)
def app_upgrade(app: str | None = None, force: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
    """Upgrade one installed YunoHost app, or all upgradable apps if none is specified.

    Blocked (PolicyViolation, not confirmable) unless a recent backup
    exists and there is enough free disk space - see policy.toml /
    policy/rules.py's DEFAULT_POLICY["apps.upgrade"].
    """
    return adapter.app_upgrade(app=app, force=force)


@mcp.tool()
@redact_response
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
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.upgrade", lock=write_lock, audit_log=audit_log)
def execute_plan(plan_id: str) -> dict[str, Any]:
    """Execute a plan previously returned by plan_app_upgrade(). Re-checks
    apps.upgrade's hard policy at execute time, not just at plan time -
    state (free space, backup age) may have drifted in between."""
    request = require_current_request()
    try:
        ticket = plan_store.consume(plan_id, pubkey=request.pubkey, tool="plan.app_upgrade", arguments={})
    except ConfirmationError as exc:
        raise ConfirmationError(f"invalid plan_id: {exc}") from exc

    rule = policy_rules.get("apps.upgrade", PolicyRule())
    _check_apps_upgrade(rule)
    return adapter.app_upgrade(app=ticket.plan["app"])


@mcp.tool()
@redact_response
@require_scope(Scope.APPS_REMOVE)
@audited_write("apps.remove", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "apps.remove",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    checks=_check_apps_remove,
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
    return adapter.app_remove(app, purge=purge)


@mcp.tool()
@redact_response
@require_scope(Scope.BACKUPS_RESTORE)
@audited_write("backups.restore", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "backups.restore",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
    return adapter.backup_restore(name, apps=apps, system=system, force=force)


@mcp.tool()
@redact_response
@require_scope(Scope.SYSTEM_UPGRADE)
@audited_write("system.upgrade", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "system.upgrade",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    plan_builder=lambda **_: {
        "action": "upgrade system packages",
        "warning": "This upgrades OS-level packages and may restart services.",
    },
)
def system_upgrade(confirmation_id: str | None = None) -> dict[str, Any]:
    """Upgrade system (OS-level) packages. Requires confirmation."""
    return adapter.system_upgrade()


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_INSPECT)
def package_inspect(source: str) -> dict[str, Any]:
    """Return the manifest and declared resources for a candidate package.

    `source` is a local path or git URL (not the app catalog) - does not
    install anything.
    """
    return adapter.package_inspect(source)


@mcp.tool()
@redact_response
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
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_install_test(source: str, label: str | None = None, args: str | None = None) -> dict[str, Any]:
    """Install a candidate package from a local path/git URL, for testing."""
    return adapter.package_install_test(source, label=label, args=args)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_upgrade_test(app: str, source: str) -> dict[str, Any]:
    """Upgrade an already-installed `app` from a candidate local path/tarball, for testing."""
    return adapter.package_upgrade_test(app, source)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_backup_test(app: str) -> dict[str, Any]:
    """Create a backup of an installed test app, to verify its backup script works."""
    return adapter.package_backup_test(app)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_restore_test(app: str, archive_name: str) -> dict[str, Any]:
    """Restore a test app from a backup archive, to verify its restore script works."""
    return adapter.package_restore_test(app, archive_name)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_change_url_test(app: str, domain: str, path: str) -> dict[str, Any]:
    """Move a test app to a new domain/path, to verify its change_url script works."""
    return adapter.package_change_url_test(app, domain, path)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_remove_test(app: str, purge: bool = True) -> dict[str, Any]:
    """Remove a test app, to verify its remove script works. Purges data by default."""
    return adapter.package_remove_test(app, purge=purge)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_INSPECT)
def package_logs(operation: str) -> dict[str, Any]:
    """Return the full log for one operation - an alias over operation_logs()
    for the package-development workflow (PLAN.md Phase 8)."""
    return adapter.operation_logs(operation)


@mcp.tool()
@redact_response
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_run_tests(source: str, app_id: str | None = None) -> dict[str, Any]:
    """Run the standard install -> backup -> remove -> restore -> remove
    cycle against a candidate package in one call. Stops at the first
    failing step; see yunohost/adapter.py's package_run_tests for exactly
    what each step does and why this isn't package_check's full CI matrix.
    """
    return adapter.package_run_tests(source, app_id=app_id)


@mcp.tool()
@redact_response
@require_scope(Scope.AUDIT_READ)
def audit_list(limit: int | None = None) -> dict[str, Any]:
    """List audit trail entries, newest first. Administrator-only (Scope.AUDIT_READ)."""
    return {"entries": audit_log.list(limit=limit)}


@mcp.tool()
@redact_response
@require_scope(Scope.AUDIT_READ)
def audit_get(audit_id: str) -> dict[str, Any]:
    """Return one audit trail entry by id. Administrator-only (Scope.AUDIT_READ)."""
    entry = audit_log.get(audit_id)
    if entry is None:
        raise ValueError(f"no audit entry with id {audit_id!r}")
    return entry


@mcp.tool()
@redact_response
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
    """Build the ASGI app for the Streamable HTTP transport: MCP wrapped in NIP-98 auth + authz."""
    inner_app = mcp.streamable_http_app()
    identity_store = IdentityStore.load(settings.identity_file_path())
    return NostrAuthMiddleware(
        inner_app,
        identity_store=identity_store,
        replay_cache=ReplayCache(ttl_seconds=settings.nip98_replay_ttl_seconds),
        clock_skew_seconds=settings.nip98_clock_skew_seconds,
        server_identity=get_server_identity(),
        revocation_store=RevocationStore.load(settings.revoked_delegations_path()),
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
