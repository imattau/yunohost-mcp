from __future__ import annotations

import pytest

from yunohost_mcp.policy.roles import ROLE_SCOPES, UnknownRoleError, scopes_for_roles
from yunohost_mcp.policy.scopes import ALL_SCOPES, Scope


def test_readonly_has_no_write_scopes():
    scopes = ROLE_SCOPES["readonly"]
    for scope in scopes:
        assert not scope.value.split(".")[-1] in {"install", "upgrade", "remove", "restart", "create", "restore", "write", "delete"}


def test_administrator_has_every_scope():
    assert ROLE_SCOPES["administrator"] == ALL_SCOPES


def test_scopes_for_multiple_roles_is_union():
    scopes = scopes_for_roles(("readonly", "operator"))
    assert Scope.SERVER_READ in scopes
    assert Scope.SERVICES_RESTART in scopes


def test_unknown_role_raises():
    with pytest.raises(UnknownRoleError):
        scopes_for_roles(("superuser",))


def test_empty_roles_yields_no_scopes():
    assert scopes_for_roles(()) == frozenset()


def test_package_developer_can_publish_a_tested_package_to_the_catalog():
    # package-developer already has packages.test, catalog.inspect, and
    # catalog.verify - publishing what it just tested is the natural next
    # step of that workflow, not a separate elevated capability. Publish
    # itself still requires confirmation (see policy/rules.py's
    # PolicyRule for "catalog.publish").
    assert Scope.CATALOG_PUBLISH in ROLE_SCOPES["package-developer"]


def test_every_role_can_refresh_update_metadata():
    # system.update (updates_refresh) only refreshes cached metadata - it
    # doesn't touch installed apps - so it sits on _READONLY next to
    # diagnosis.read, meaning every role built on top of readonly gets it
    # too. Confirms it after the catalog.publish workflow: publishing a
    # package and then wanting to see it in the live catalog is exactly
    # why this tool exists.
    for role in ROLE_SCOPES:
        assert Scope.SYSTEM_UPDATE in ROLE_SCOPES[role], role
