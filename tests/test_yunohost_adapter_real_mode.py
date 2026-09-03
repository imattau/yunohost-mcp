"""Regression tests for the real (fake_yunohost=False) adapter code paths.

This sandbox has no real `yunohost` package installed, so these build fake
`yunohost.*` modules under sys.modules whose decorated functions faithfully
reproduce `@is_unit_operation`'s actual argument-remapping behavior (copied
from /tmp/yunohost-src's src/log.py at review time) - the same decorator
that wraps app_remove, tools_upgrade, and diagnosis_run in the real
codebase (app_install/app_upgrade and backup_create/backup_restore now go
through _call_via_system_python instead - see
test_yunohost_adapter_system_python.py).

Why this matters: the decorator constructs its own OperationLogger
internally and prepends it to the call - callers must NOT pass one. An
earlier version of yunohost/adapter.py did pass one, which (as reproduced
here) silently corrupts the *other* arguments rather than raising - e.g.
app_install's real `app` argument ends up in `label`, and the caller's
OperationLogger object ends up in `app`. These tests catch that class of
bug by asserting the underlying function receives the real, correctly
positioned arguments - not just that "some result came back".
"""

from __future__ import annotations

import types
from inspect import signature
from typing import Any

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter


def _is_unit_operation():
    """Faithful reproduction of yunohost.log.is_unit_operation's argument
    remapping (see /tmp/yunohost-src's src/log.py:444 at review time) -
    enough of it to reproduce the corruption bug if it recurs, without
    pulling in the rest of OperationLogger/moulinette."""

    def decorate(func):
        def func_wrapper(*args, **kwargs):
            if len(args) > 0:
                keys = list(signature(func).parameters.keys())
                if "operation_logger" in keys:
                    keys.remove("operation_logger")
                for k, arg in enumerate(args):
                    kwargs[keys[k]] = arg
                args = ()
            return func(FAKE_OPERATION_LOGGER, *args, **kwargs)

        return func_wrapper

    return decorate


class _FakeOperationLogger:
    """Stand-in for yunohost.log.OperationLogger: distinguishable from a
    real argument value, so a corrupted call is easy to detect."""

    def __repr__(self) -> str:
        return "<FakeOperationLogger>"


FAKE_OPERATION_LOGGER = _FakeOperationLogger()


@pytest.fixture
def real_mode_adapter(monkeypatch: pytest.MonkeyPatch) -> YunohostAdapter:
    calls: dict[str, dict[str, Any]] = {}

    @_is_unit_operation()
    def app_remove(operation_logger, app, purge=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(app, str), f"app corrupted: got {app!r}"
        calls["app_remove"] = {"app": app, "purge": purge}
        return None

    yunohost_app = types.ModuleType("yunohost.app")
    yunohost_app.app_remove = app_remove

    # app_install/app_upgrade and backup_create/backup_restore are NOT
    # exercised here - none of them go through _import_attr at all
    # anymore (see test_yunohost_adapter_system_python.py): all four now
    # route through _call_via_system_python, a subprocess call, so
    # injecting fake yunohost.app/yunohost.backup submodules into this
    # process's sys.modules wouldn't reach them.

    @_is_unit_operation()
    def tools_upgrade(operation_logger, target=None, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert target == "system", f"target corrupted: got {target!r}"
        calls["tools_upgrade"] = {"target": target}
        return None

    @_is_unit_operation()
    def tools_update(operation_logger, target=None, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert target in ("system", "apps", "all"), f"target corrupted: got {target!r}"
        calls["tools_update"] = {"target": target}
        return {"apps": [], "system": []}

    # tools_migrations_run is NOT @is_unit_operation-decorated either (it
    # builds its own OperationLogger per migration internally, like
    # app_upgrade) - same "must not receive one" check as service_restart.
    def tools_migrations_run(targets=None, **_):
        calls["tools_migrations_run"] = {"targets": targets}

    def tools_migrations_state(**_):
        return {"migrations": {}}

    yunohost_tools = types.ModuleType("yunohost.tools")
    yunohost_tools.tools_upgrade = tools_upgrade
    yunohost_tools.tools_update = tools_update
    yunohost_tools.tools_migrations_run = tools_migrations_run
    yunohost_tools.tools_migrations_state = tools_migrations_state

    @_is_unit_operation()
    def diagnosis_run(operation_logger, categories=None, force=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert categories is None or isinstance(categories, list), f"categories corrupted: got {categories!r}"
        calls["diagnosis_run"] = {"categories": categories}
        return {}

    yunohost_diagnosis = types.ModuleType("yunohost.diagnosis")
    yunohost_diagnosis.diagnosis_run = diagnosis_run

    def log_list(limit=None, **_):
        return {"operation": [{"name": "20260903-000000-fake_op"}]}

    class OperationLogger:
        """Real yunohost.log.OperationLogger is never called by a fixed
        adapter, but a regressed one must fail the *content* assertions
        above, not just an AttributeError on this class being absent."""

        def __init__(self, *args, **kwargs) -> None:
            pass

    yunohost_log = types.ModuleType("yunohost.log")
    yunohost_log.log_list = log_list
    yunohost_log.OperationLogger = OperationLogger

    def service_restart(names, **_):
        calls["service_restart"] = {"names": names}

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_restart = service_restart

    # None of firewall_{list,is_open,open,close,reload} are
    # @is_unit_operation-decorated either - same "must not receive an
    # operation_logger" check as service_restart.
    def firewall_open(port, protocol, comment, **_):
        calls["firewall_open"] = {"port": port, "protocol": protocol, "comment": comment}

    yunohost_firewall = types.ModuleType("yunohost.firewall")
    yunohost_firewall.firewall_open = firewall_open

    # domain_add is NOT exercised here either - like app_install/
    # app_upgrade and backup_create/backup_restore, it now routes through
    # _call_via_system_python (see test_yunohost_adapter_system_python.py),
    # so injecting a fake yunohost.domain submodule wouldn't reach it.
    # app_change_url is excluded for the same reason - it imports
    # yunohost.utils.form too.
    yunohost_domain = types.ModuleType("yunohost.domain")

    @_is_unit_operation()
    def user_create(operation_logger, username, domain, password, fullname, mailbox_quota="0", admin=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(username, str), f"username corrupted: got {username!r}"
        calls["user_create"] = {
            "username": username,
            "domain": domain,
            "fullname": fullname,
            "mailbox_quota": mailbox_quota,
            "admin": admin,
        }
        return {"fullname": fullname, "username": username}

    @_is_unit_operation()
    def user_update(operation_logger, username, fullname=None, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(username, str), f"username corrupted: got {username!r}"
        calls["user_update"] = {"username": username, "fullname": fullname}
        return None

    @_is_unit_operation()
    def user_delete(operation_logger, username, purge=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(username, str), f"username corrupted: got {username!r}"
        calls["user_delete"] = {"username": username, "purge": purge}
        return None

    @_is_unit_operation()
    def user_group_create(operation_logger, groupname, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(groupname, str), f"groupname corrupted: got {groupname!r}"
        calls["user_group_create"] = {"groupname": groupname}
        return {"groupname": groupname}

    @_is_unit_operation()
    def user_group_update(operation_logger, groupname, add=None, remove=None, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(groupname, str), f"groupname corrupted: got {groupname!r}"
        calls["user_group_update"] = {"groupname": groupname, "add": add, "remove": remove}
        return None

    @_is_unit_operation()
    def user_group_delete(operation_logger, groupname, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(groupname, str), f"groupname corrupted: got {groupname!r}"
        calls["user_group_delete"] = {"groupname": groupname}
        return None

    # user_permission_add/user_permission_remove are @is_flash_unit_operation
    # (flash=True) in the real code - log.py's is_unit_operation() never
    # prepends an OperationLogger when flash=True, so these two never take
    # one at all. Plain functions here, not wrapped in _is_unit_operation().
    def user_permission_add(permission, names, **_):
        calls["user_permission_add"] = {"permission": permission, "names": names}
        return {"allowed": names}

    def user_permission_remove(permission, names, **_):
        calls["user_permission_remove"] = {"permission": permission, "names": names}
        return {"allowed": []}

    yunohost_user = types.ModuleType("yunohost.user")
    yunohost_user.user_create = user_create
    yunohost_user.user_update = user_update
    yunohost_user.user_delete = user_delete
    yunohost_user.user_group_create = user_group_create
    yunohost_user.user_group_update = user_group_update
    yunohost_user.user_group_delete = user_group_delete
    yunohost_user.user_permission_add = user_permission_add
    yunohost_user.user_permission_remove = user_permission_remove

    def certificate_status(domains, **_):
        return {"certificates": {d: {"CA_type": "selfsigned"} for d in domains}}

    yunohost_certificate = types.ModuleType("yunohost.certificate")
    yunohost_certificate.certificate_status = certificate_status

    for name, module in {
        "yunohost.app": yunohost_app,
        "yunohost.tools": yunohost_tools,
        "yunohost.diagnosis": yunohost_diagnosis,
        "yunohost.log": yunohost_log,
        "yunohost.service": yunohost_service,
        "yunohost.firewall": yunohost_firewall,
        "yunohost.domain": yunohost_domain,
        "yunohost.certificate": yunohost_certificate,
        "yunohost.user": yunohost_user,
    }.items():
        monkeypatch.setitem(__import__("sys").modules, name, module)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter._test_calls = calls  # type: ignore[attr-defined]
    return adapter


def test_app_remove_receives_correct_app_name_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.app_remove("nextcloud", purge=True)
    assert real_mode_adapter._test_calls["app_remove"] == {"app": "nextcloud", "purge": True}


def test_system_upgrade_receives_correct_target_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.system_upgrade()
    assert real_mode_adapter._test_calls["tools_upgrade"] == {"target": "system"}


def test_diagnosis_run_receives_correct_categories_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.diagnosis_run(categories=["ip"])
    assert real_mode_adapter._test_calls["diagnosis_run"] == {"categories": ["ip"]}


def test_updates_refresh_receives_correct_target_not_operation_logger(real_mode_adapter: YunohostAdapter):
    result = real_mode_adapter.updates_refresh(target="apps")
    assert real_mode_adapter._test_calls["tools_update"] == {"target": "apps"}
    assert result == {"fake": False, "target": "apps", "apps": [], "system": []}


def test_service_restart_unaffected(real_mode_adapter: YunohostAdapter):
    # service_restart is NOT @is_unit_operation-decorated, so it should
    # never have received a caller-constructed OperationLogger in the
    # first place - confirming the fix didn't touch what was already
    # correct.
    real_mode_adapter.service_restart(["nginx"])
    assert real_mode_adapter._test_calls["service_restart"] == {"names": ["nginx"]}


def test_migrations_run_unaffected(real_mode_adapter: YunohostAdapter):
    # tools_migrations_run is NOT @is_unit_operation-decorated - same class
    # of check as service_restart above, not the argument-remapping bug.
    real_mode_adapter.migrations_run(targets=["0027_migrate_to_bookworm"])
    assert real_mode_adapter._test_calls["tools_migrations_run"] == {"targets": ["0027_migrate_to_bookworm"]}


def test_firewall_open_unaffected(real_mode_adapter: YunohostAdapter):
    # firewall_open is NOT @is_unit_operation-decorated - same class of
    # check as service_restart above, not the argument-remapping bug.
    real_mode_adapter.firewall_open(8080, "tcp", comment="test")
    assert real_mode_adapter._test_calls["firewall_open"] == {"port": 8080, "protocol": "tcp", "comment": "test"}


def test_user_create_receives_correct_username_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_create("alice", domain="example.com", password="hunter2", fullname="Alice Example")
    assert real_mode_adapter._test_calls["user_create"] == {
        "username": "alice",
        "domain": "example.com",
        "fullname": "Alice Example",
        "mailbox_quota": "0",
        "admin": False,
    }


def test_user_update_receives_correct_username_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_update("alice", fullname="Alice New")
    assert real_mode_adapter._test_calls["user_update"] == {"username": "alice", "fullname": "Alice New"}


def test_user_delete_receives_correct_username_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_delete("alice", purge=True)
    assert real_mode_adapter._test_calls["user_delete"] == {"username": "alice", "purge": True}


def test_user_group_create_receives_correct_groupname_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_group_create("editors")
    assert real_mode_adapter._test_calls["user_group_create"] == {"groupname": "editors"}


def test_user_group_update_receives_correct_groupname_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_group_update("editors", add=["alice"])
    assert real_mode_adapter._test_calls["user_group_update"] == {
        "groupname": "editors",
        "add": ["alice"],
        "remove": None,
    }


def test_user_group_delete_receives_correct_groupname_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_group_delete("editors")
    assert real_mode_adapter._test_calls["user_group_delete"] == {"groupname": "editors"}


def test_user_permission_add_unaffected(real_mode_adapter: YunohostAdapter):
    # user_permission_add/remove are @is_flash_unit_operation (flash=True),
    # so - like service_restart - they never receive an OperationLogger at
    # all; nothing for the corruption bug to have a chance to hit.
    real_mode_adapter.user_permission_add("myapp.main", ["alice"])
    assert real_mode_adapter._test_calls["user_permission_add"] == {"permission": "myapp.main", "names": ["alice"]}


def test_user_permission_remove_unaffected(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.user_permission_remove("myapp.main", ["alice"])
    assert real_mode_adapter._test_calls["user_permission_remove"] == {
        "permission": "myapp.main",
        "names": ["alice"],
    }
