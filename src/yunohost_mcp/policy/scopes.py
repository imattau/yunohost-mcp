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

    SYSTEM_UPDATE = "system.update"
    SYSTEM_UPGRADE = "system.upgrade"

    PACKAGES_INSPECT = "packages.inspect"
    PACKAGES_TEST = "packages.test"

    # Not granted by any role except administrator (policy/roles.py) - this
    # is what makes audit_list()/audit_get() "administrator-only" per
    # PLAN.md Phase 10, without a role-name check in the tool itself.
    AUDIT_READ = "audit.read"

    # Same pattern, for Phase 13's owner co-signing: only administrator may
    # call approve_operation() to co-sign another identity's pending
    # high-risk confirmation (policy/rules.py's require_owner_signature).
    OWNER_APPROVE = "owner.approve"


ALL_SCOPES: frozenset[Scope] = frozenset(Scope)
