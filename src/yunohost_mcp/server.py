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
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import inspect
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

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
from yunohost_mcp.auth.owner import resolve_owner_pubkey
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.auth.server_identity import ServerIdentity
from yunohost_mcp.config import load_settings
from yunohost_mcp.notify import notify_owner_best_effort, parse_relay_list
from yunohost_mcp.policy.confirmation import ConfirmationError, ConfirmationStore, ConfirmationTicket
from yunohost_mcp.policy.enforcement import (
    require_confirmation,
    require_scope,
    set_owner_signature_pending_hook,
    translate_known_errors,
)
from yunohost_mcp.policy.locks import WriteLock
from yunohost_mcp.policy.rules import PolicyRule, PolicyViolation, check_free_space, check_recent_backup, load_policy
from yunohost_mcp.policy.scopes import Scope
from yunohost_mcp.redaction import redact_response
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostAdapter

settings = load_settings()
adapter = YunohostAdapter(settings=settings)
write_lock = WriteLock()
audit_log = AuditLog(path=settings.audit_log_path())
policy_rules = load_policy(settings.policy_file_path())
confirmation_store = ConfirmationStore(
    ttl_seconds=settings.confirmation_ttl_seconds,
    owner_approval_ttl_seconds=settings.owner_approval_ttl_seconds,
)
plan_store = ConfirmationStore(ttl_seconds=settings.confirmation_ttl_seconds)
catalog_plan_store = ConfirmationStore(ttl_seconds=settings.confirmation_ttl_seconds)
# Shared with create_http_app() below (not just constructed there) so
# get_owner_pubkey() can resolve the bootstrap-administrator fallback
# (auth/owner.py) against the same live-reloaded identity.toml the HTTP
# transport itself authenticates against, on stdio too (LOCAL_STDIO_REQUEST
# never has a real npub, but approve_operation is still reachable there).
identity_store = IdentityStore.live(settings.identity_file_path())


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


set_owner_signature_pending_hook(_notify_owner_pending)


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


def _check_apps_upgrade(rule: PolicyRule) -> None:
    check_free_space(rule)
    check_recent_backup(rule, archive_created_at=adapter.backup_created_at_times(), now=time.time())


def _check_apps_remove(rule: PolicyRule) -> None:
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
    return adapter.domain_add(domain, install_letsencrypt_cert=install_letsencrypt_cert)


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
    return adapter.domain_cert_install(domain, letsencrypt=letsencrypt, staging=staging)


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
    "users.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
        username, domain=domain, password=password, fullname=fullname, mailbox_quota=mailbox_quota, admin=admin
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
    return adapter.user_delete(username, purge=purge)


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
    plan_builder=lambda groupname, **_: {"action": "create group", "groupname": groupname},
)
def user_group_create(groupname: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Create a new YunoHost user group - a prerequisite for granting a
    custom set of users access to an app permission (see
    user_permission_add) rather than an individual username."""
    return adapter.user_group_create(groupname)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
    return adapter.user_group_update(groupname, add=add, remove=remove)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_DELETE)
@audited_write("users.delete", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.delete",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    plan_builder=lambda groupname, **_: {
        "action": "delete group",
        "groupname": groupname,
        "warning": "Irreversible. Any permissions granted to this group are revoked.",
    },
)
def user_group_delete(groupname: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Delete a YunoHost user group. Requires owner co-signature
    (approve_operation) in addition to confirmation - see PLAN.md Phase 13."""
    return adapter.user_group_delete(groupname)


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
    return adapter.user_permission_add(permission, names)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.USERS_WRITE)
@audited_write("users.permissions", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "users.permissions",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
    return adapter.user_permission_remove(permission, names)


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
def service_restart(names: list[str]) -> dict[str, Any]:
    """Restart one or more YunoHost services."""
    return adapter.service_restart(names)


@mcp.tool()
@redact_response
@translate_known_errors
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
@translate_known_errors
@require_scope(Scope.APPS_INSTALL)
@audited_write("apps.install", lock=write_lock, audit_log=audit_log)
def app_install(app: str, label: str | None = None, args: str | None = None, force: bool = False) -> dict[str, Any]:
    """Install a YunoHost app."""
    return adapter.app_install(app, label=label, args=args, force=force)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.upgrade", lock=write_lock, audit_log=audit_log)
@require_confirmation("apps.upgrade", policy=policy_rules, confirmation_store=confirmation_store, checks=_check_apps_upgrade)
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
    return adapter.app_upgrade(app=app, force=force, url=url)


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
@translate_known_errors
# Reuses APPS_UPGRADE rather than a new scope: both roles that can already
# reach for app_remove-and-reinstall as a change_url workaround
# (app-admin, package-developer) already hold APPS_UPGRADE too, so this
# closes that gap for both without a role/identity.toml change.
@require_scope(Scope.APPS_UPGRADE)
@audited_write("apps.change_url", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "apps.change_url",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
    return adapter.app_change_url(app, domain=domain, path=path)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.APPS_CONFIG_WRITE)
@audited_write("apps.config", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "apps.config",
    policy=policy_rules,
    confirmation_store=confirmation_store,
    plan_builder=lambda app, key, value, **_: {
        "action": "set app config",
        "app": app,
        "key": key,
        "value": value,
        "warning": "Applies immediately and typically restarts the app's service. "
        "Call app_config_get(app, full=True) first to confirm this is the exact key you mean.",
    },
)
def app_config_set(app: str, key: str, value: str, confirmation_id: str | None = None) -> dict[str, Any]:
    """Set one config-panel setting on an installed app. Requires confirmation.

    `key` must be the exact dotted "<panel>.<section>.<option>" id from
    app_config_get(app, full=True) - a panel can reuse the same bare
    option name across sections, so a shortened key can silently target
    the wrong setting. Applying typically restarts the app's service.
    """
    return adapter.app_config_set(app, key=key, value=value)


@mcp.tool()
@redact_response
@translate_known_errors
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
@translate_known_errors
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
    return adapter.firewall_open(port, protocol, comment=comment, upnp=upnp, no_reload=no_reload)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_WRITE)
@audited_write("firewall.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "firewall.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
    return adapter.firewall_close(port, protocol, upnp_only=upnp_only, no_reload=no_reload)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.FIREWALL_WRITE)
@audited_write("firewall.write", lock=write_lock, audit_log=audit_log)
@require_confirmation(
    "firewall.write",
    policy=policy_rules,
    confirmation_store=confirmation_store,
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
    return adapter.firewall_reload(skip_upnp=skip_upnp)


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
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_install_test(source: str, label: str | None = None, args: str | None = None) -> dict[str, Any]:
    """Install a candidate package from a local path/git URL, for testing."""
    return adapter.package_install_test(source, label=label, args=args)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_upgrade_test(app: str, source: str) -> dict[str, Any]:
    """Upgrade an already-installed `app` from a candidate local path/tarball, for testing."""
    return adapter.package_upgrade_test(app, source)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_backup_test(app: str) -> dict[str, Any]:
    """Create a backup of an installed test app, to verify its backup script works."""
    return adapter.package_backup_test(app)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_restore_test(app: str, archive_name: str) -> dict[str, Any]:
    """Restore a test app from a backup archive, to verify its restore script works."""
    return adapter.package_restore_test(app, archive_name)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_change_url_test(app: str, domain: str, path: str) -> dict[str, Any]:
    """Move a test app to a new domain/path, to verify its change_url script works."""
    return adapter.package_change_url_test(app, domain, path)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_TEST)
@audited_write("packages.test", lock=write_lock, audit_log=audit_log)
def package_remove_test(app: str, purge: bool = True) -> dict[str, Any]:
    """Remove a test app, to verify its remove script works. Purges data by default."""
    return adapter.package_remove_test(app, purge=purge)


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.PACKAGES_INSPECT)
def package_logs(operation: str, tail_lines: int | None = None) -> dict[str, Any]:
    """Return the log for one operation - an alias over operation_logs()
    for the package-development workflow (PLAN.md Phase 8). See that
    tool's docstring for the default tail size and log-text redaction."""
    return adapter.operation_logs(operation, tail_lines=tail_lines)


@mcp.tool()
@redact_response
@translate_known_errors
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
@translate_known_errors
@require_scope(Scope.AUDIT_READ)
def audit_list(limit: int | None = None) -> dict[str, Any]:
    """List audit trail entries, newest first. Administrator-only (Scope.AUDIT_READ)."""
    return {"entries": audit_log.list(limit=limit)}


@mcp.tool()
@redact_response
@translate_known_errors
@require_scope(Scope.AUDIT_READ)
def audit_get(audit_id: str) -> dict[str, Any]:
    """Return one audit trail entry by id. Administrator-only (Scope.AUDIT_READ)."""
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
    that just wants to know whether to retry the original call yet."""
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
def safe_upgrade(app: str) -> dict[str, Any]:
    """PLAN.md Phase 14's flagship workflow: diagnosis -> inspect app ->
    create a fresh safety backup -> upgrade -> check app/HTTP endpoint ->
    re-diagnose -> one report. Runs through apps.upgrade's own policy: free
    space is checked up front (nothing in this workflow can create disk
    space), and the backup requirement is re-verified after this workflow's
    own backup step actually happens, not just assumed to have worked.
    """
    rule = policy_rules.get("apps.upgrade", PolicyRule())
    check_free_space(rule)
    result = adapter.safe_upgrade(app)
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
def test_package(source: str, app_id: str | None = None) -> dict[str, Any]:
    """Alias for package_run_tests() - PLAN.md Phase 14 names this
    separately from Phase 8's package_run_tests, but it's the same
    install -> backup -> remove -> restore cycle; see
    yunohost/adapter.py's package_run_tests for what each step does.
    """
    return adapter.package_run_tests(source, app_id=app_id)


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
