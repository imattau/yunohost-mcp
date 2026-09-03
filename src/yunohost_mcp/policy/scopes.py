"""Scopes: the underlying authorization primitive (PLAN.md Phase 3).

Roles (policy/roles.py) are just named groups of these. Tool handlers
should always check a Scope, never a role directly, so role definitions
can change without touching tool code.
"""

from __future__ import annotations

from enum import StrEnum


class Scope(StrEnum):
    SERVER_READ = "server.read"

    DIAGNOSIS_READ = "diagnosis.read"

    APPS_READ = "apps.read"
    APPS_INSTALL = "apps.install"
    APPS_UPGRADE = "apps.upgrade"
    APPS_REMOVE = "apps.remove"

    SERVICES_READ = "services.read"
    SERVICES_RESTART = "services.restart"

    LOGS_READ = "logs.read"

    BACKUPS_READ = "backups.read"
    BACKUPS_CREATE = "backups.create"
    BACKUPS_RESTORE = "backups.restore"

    USERS_READ = "users.read"
    USERS_WRITE = "users.write"
    USERS_DELETE = "users.delete"

    DOMAINS_READ = "domains.read"
    DOMAINS_WRITE = "domains.write"

    # Refreshes cached metadata only (apt cache, app catalog sources) -
    # yunohost_mcp.yunohost.adapter.YunohostAdapter.updates_refresh(). Not
    # to be confused with SYSTEM_UPGRADE, which actually installs updates.
    SYSTEM_UPDATE = "system.update"
    SYSTEM_UPGRADE = "system.upgrade"
    # Actually running/skipping a migration (tools_migrations_run) -
    # listing/state (migrations_list/migrations_state) sit under
    # SYSTEM_UPDATE instead, same as pending_migrations already surfacing
    # passively through validate_server/updates_refresh. Administrator-only,
    # like SYSTEM_UPGRADE - migrations can carry irreversible OS/schema
    # changes (e.g. a Debian version bump) in the same risk class.
    SYSTEM_MIGRATE = "system.migrate"

    # firewall_list/firewall_is_open - read-only, safe for every role that
    # already gets services.read/domains.read.
    FIREWALL_READ = "firewall.read"
    # firewall_open/close/allow/disallow/reload/upnp/stop. Administrator-only
    # and owner-co-signed (policy/rules.py) - a wrong port/rule can lock the
    # admin out of their own server with no MCP-level undo, PLAN.md's named
    # example of exactly the risk class system.upgrade/backups.restore are
    # already gated at.
    FIREWALL_WRITE = "firewall.write"

    PACKAGES_INSPECT = "packages.inspect"
    PACKAGES_TEST = "packages.test"

    CATALOG_INSPECT = "catalog.inspect"
    CATALOG_VERIFY = "catalog.verify"
    CATALOG_PUBLISH = "catalog.publish"

    # Not granted by any role except administrator (policy/roles.py) - this
    # is what makes audit_list()/audit_get() "administrator-only" per
    # PLAN.md Phase 10, without a role-name check in the tool itself.
    AUDIT_READ = "audit.read"

    # Same pattern, for Phase 13's owner co-signing: only administrator may
    # call approve_operation() to co-sign another identity's pending
    # high-risk confirmation (policy/rules.py's require_owner_signature).
    OWNER_APPROVE = "owner.approve"


ALL_SCOPES: frozenset[Scope] = frozenset(Scope)
