"""Regression tests for the real (fake_yunohost=False) adapter code paths.

This sandbox has no real `yunohost` package installed, so these build fake
`yunohost.*` modules under sys.modules whose decorated functions faithfully
reproduce `@is_unit_operation`'s actual argument-remapping behavior (copied
from /tmp/yunohost-src's src/log.py at review time) - the same decorator
that wraps app_install, app_remove, backup_create, tools_upgrade, and
diagnosis_run in the real codebase.

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
    def app_install(operation_logger, app, label=None, args=None, force=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(app, str), f"app corrupted: got {app!r}"
        calls["app_install"] = {"app": app, "label": label}
        return {"notifications": {}}

    @_is_unit_operation()
    def app_remove(operation_logger, app, purge=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(app, str), f"app corrupted: got {app!r}"
        calls["app_remove"] = {"app": app, "purge": purge}
        return None

    def app_upgrade(app=None, force=False, **_):
        calls["app_upgrade"] = {"app": app}
        return {"success": [app] if isinstance(app, str) else app}

    yunohost_app = types.ModuleType("yunohost.app")
    yunohost_app.app_install = app_install
    yunohost_app.app_remove = app_remove
    yunohost_app.app_upgrade = app_upgrade

    @_is_unit_operation()
    def backup_create(operation_logger, name=None, description=None, apps=None, system=None, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert name is None or isinstance(name, str), f"name corrupted: got {name!r}"
        calls["backup_create"] = {"name": name, "apps": apps}
        return {"name": name or "auto-name"}

    def backup_restore(name, apps=None, system=None, force=False, **_):
        assert isinstance(name, str), f"name corrupted: got {name!r}"
        calls["backup_restore"] = {"name": name, "apps": apps}
        return None

    yunohost_backup = types.ModuleType("yunohost.backup")
    yunohost_backup.backup_create = backup_create
    yunohost_backup.backup_restore = backup_restore

    @_is_unit_operation()
    def tools_upgrade(operation_logger, target=None, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert target == "system", f"target corrupted: got {target!r}"
        calls["tools_upgrade"] = {"target": target}
        return None

    yunohost_tools = types.ModuleType("yunohost.tools")
    yunohost_tools.tools_upgrade = tools_upgrade

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

    for name, module in {
        "yunohost.app": yunohost_app,
        "yunohost.backup": yunohost_backup,
        "yunohost.tools": yunohost_tools,
        "yunohost.diagnosis": yunohost_diagnosis,
        "yunohost.log": yunohost_log,
        "yunohost.service": yunohost_service,
    }.items():
        monkeypatch.setitem(__import__("sys").modules, name, module)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter._test_calls = calls  # type: ignore[attr-defined]
    return adapter


def test_app_install_receives_correct_app_name_not_operation_logger(real_mode_adapter: YunohostAdapter):
    result = real_mode_adapter.app_install("nextcloud", label="My Cloud")
    assert real_mode_adapter._test_calls["app_install"] == {"app": "nextcloud", "label": "My Cloud"}
    assert result["operation_id"] == "20260903-000000-fake_op"


def test_app_remove_receives_correct_app_name_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.app_remove("nextcloud", purge=True)
    assert real_mode_adapter._test_calls["app_remove"] == {"app": "nextcloud", "purge": True}


def test_backup_create_receives_correct_name_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.backup_create(name="my-backup", apps=["nextcloud"])
    assert real_mode_adapter._test_calls["backup_create"] == {"name": "my-backup", "apps": ["nextcloud"]}


def test_system_upgrade_receives_correct_target_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.system_upgrade()
    assert real_mode_adapter._test_calls["tools_upgrade"] == {"target": "system"}


def test_diagnosis_run_receives_correct_categories_not_operation_logger(real_mode_adapter: YunohostAdapter):
    real_mode_adapter.diagnosis_run(categories=["ip"])
    assert real_mode_adapter._test_calls["diagnosis_run"] == {"categories": ["ip"]}


def test_app_upgrade_and_backup_restore_and_service_restart_unaffected(real_mode_adapter: YunohostAdapter):
    # These three are NOT @is_unit_operation-decorated, so they should never
    # have received a caller-constructed OperationLogger in the first
    # place - confirming the fix didn't touch what was already correct.
    real_mode_adapter.app_upgrade(app="nextcloud")
    real_mode_adapter.backup_restore("20260901-000000", apps=["nextcloud"])
    real_mode_adapter.service_restart(["nginx"])
    assert real_mode_adapter._test_calls["app_upgrade"] == {"app": "nextcloud"}
    assert real_mode_adapter._test_calls["backup_restore"] == {"name": "20260901-000000", "apps": ["nextcloud"]}
    assert real_mode_adapter._test_calls["service_restart"] == {"names": ["nginx"]}
