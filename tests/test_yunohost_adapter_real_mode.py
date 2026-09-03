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

    yunohost_tools = types.ModuleType("yunohost.tools")
    yunohost_tools.tools_upgrade = tools_upgrade
    yunohost_tools.tools_update = tools_update

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

    @_is_unit_operation()
    def domain_add(operation_logger, domain, ignore_dyndns=False, install_letsencrypt_cert=False, **_):
        assert operation_logger is FAKE_OPERATION_LOGGER
        assert isinstance(domain, str), f"domain corrupted: got {domain!r}"
        calls["domain_add"] = {
            "domain": domain,
            "ignore_dyndns": ignore_dyndns,
            "install_letsencrypt_cert": install_letsencrypt_cert,
        }
        return None

    yunohost_domain = types.ModuleType("yunohost.domain")
    yunohost_domain.domain_add = domain_add

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
        "yunohost.domain": yunohost_domain,
        "yunohost.certificate": yunohost_certificate,
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


def test_domain_add_receives_correct_domain_not_operation_logger_and_always_ignores_dyndns(
    real_mode_adapter: YunohostAdapter,
):
    result = real_mode_adapter.domain_add("new-app.example.nohost.me", install_letsencrypt_cert=True)
    assert real_mode_adapter._test_calls["domain_add"] == {
        "domain": "new-app.example.nohost.me",
        "ignore_dyndns": True,
        "install_letsencrypt_cert": True,
    }
    assert result == {
        "fake": False,
        "operation_id": "20260903-000000-fake_op",
        "domain": "new-app.example.nohost.me",
        "certificate": {"CA_type": "selfsigned"},
    }


def test_service_restart_unaffected(real_mode_adapter: YunohostAdapter):
    # service_restart is NOT @is_unit_operation-decorated, so it should
    # never have received a caller-constructed OperationLogger in the
    # first place - confirming the fix didn't touch what was already
    # correct.
    real_mode_adapter.service_restart(["nginx"])
    assert real_mode_adapter._test_calls["service_restart"] == {"names": ["nginx"]}
