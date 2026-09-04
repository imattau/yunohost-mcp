"""Roles: named, fixed groupings of scopes (PLAN.md Phase 3).

Roles are a convenience for identity.toml authors, not a security
primitive of their own — an IdentityRecord's effective scopes are just the
union of ROLE_SCOPES[role] for each of its roles. There is no per-identity
scope override in Phase 3; if that's ever needed, it should be additive and
explicit in identity.toml, not a way to exceed a role's scopes.

Strictly hierarchical below administrator: readonly < operator < app-admin
< package-developer, each a superset of the one before plus its own
scopes. This was previously "package-developer is not app-admin, roles
combine by union" (two independent, partially-overlapping branches) -
changed because that split didn't match how the roles were actually being
granted in practice: an identity doing real day-to-day admin work (not
just fast install/upgrade/remove iteration) still needed package-developer
specifically for packages.test/catalog.publish, but was then missing
app-admin's users.delete/backups.restore for no principled reason. Keep
this ordering when adding a new role or scope: decide which existing role
it extends, not a fresh disjoint set.
"""

from __future__ import annotations

from yunohost_mcp.policy.scopes import ALL_SCOPES, Scope

_READONLY: frozenset[Scope] = frozenset(
    {
        Scope.SERVER_READ,
        Scope.DIAGNOSIS_READ,
        Scope.SYSTEM_UPDATE,
        Scope.APPS_READ,
        Scope.SERVICES_READ,
        Scope.LOGS_READ,
        Scope.BACKUPS_READ,
        Scope.USERS_READ,
        Scope.DOMAINS_READ,
        Scope.PACKAGES_INSPECT,
        Scope.CATALOG_INSPECT,
        Scope.CATALOG_VERIFY,
        Scope.FIREWALL_READ,
        Scope.APPS_CONFIG_READ,
    }
)

_OPERATOR: frozenset[Scope] = _READONLY | {
    Scope.SERVICES_RESTART,
    Scope.BACKUPS_CREATE,
}

_APP_ADMIN: frozenset[Scope] = _OPERATOR | {
    Scope.APPS_INSTALL,
    Scope.APPS_UPGRADE,
    Scope.APPS_REMOVE,
    Scope.APPS_CONFIG_WRITE,
    Scope.BACKUPS_RESTORE,
    Scope.DOMAINS_WRITE,
    Scope.USERS_WRITE,
    Scope.USERS_DELETE,
    Scope.SYSTEM_UPGRADE,
}

_PACKAGE_DEVELOPER: frozenset[Scope] = _APP_ADMIN | {
    Scope.PACKAGES_TEST,
    Scope.CATALOG_PUBLISH,
}

_ADMINISTRATOR: frozenset[Scope] = ALL_SCOPES

ROLE_SCOPES: dict[str, frozenset[Scope]] = {
    "readonly": _READONLY,
    "operator": _OPERATOR,
    "app-admin": _APP_ADMIN,
    "package-developer": _PACKAGE_DEVELOPER,
    "administrator": _ADMINISTRATOR,
}


class UnknownRoleError(ValueError):
    """identity.toml references a role name that ROLE_SCOPES doesn't define."""


def scopes_for_roles(roles: tuple[str, ...]) -> frozenset[Scope]:
    """Union of scopes granted by each role. Raises UnknownRoleError on a typo'd role name."""
    result: set[Scope] = set()
    for role in roles:
        try:
            result |= ROLE_SCOPES[role]
        except KeyError:
            raise UnknownRoleError(
                f"unknown role {role!r}; known roles: {sorted(ROLE_SCOPES)}"
            ) from None
    return frozenset(result)
