"""Regression test: real yunohost.* calls must initialize moulinette's i18n.

yunohost.service (and other modules) call into m18n.key_exists()/m18n.n(),
but m18n.translator is only set up by moulinette.cli()/moulinette.api() -
the normal CLI/API bootstrap the adapter deliberately bypasses by importing
yunohost.* directly in-process. Skipping this raised:
    AttributeError: 'Moulinette18n' object has no attribute 'translator'
the first time a real deployment called services_list/service_status (see
session notes: caught live against a real YunoHost host after fixing a
separate venv-isolation packaging bug that had been masking this one).
"""

from __future__ import annotations

import types

import pytest

import yunohost_mcp.yunohost.adapter as adapter_module
from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter


@pytest.fixture(autouse=True)
def _reset_i18n_init_flag(monkeypatch: pytest.MonkeyPatch):
    # _ensure_i18n_initialized() only runs its body once per process
    # (module-level flag) - reset it so each test observes a fresh call.
    monkeypatch.setattr(adapter_module, "_i18n_initialized", False)


def test_real_yunohost_call_initializes_i18n_before_use(monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []

    def fake_init_i18n() -> None:
        calls.append("init_i18n")

    yunohost_pkg = types.ModuleType("yunohost")
    yunohost_pkg.init_i18n = fake_init_i18n
    monkeypatch.setitem(__import__("sys").modules, "yunohost", yunohost_pkg)

    def service_status(names, **_):
        # A real yunohost.service would AttributeError here on
        # m18n.translator if init_i18n() hadn't already run.
        assert calls == ["init_i18n"], "yunohost.* was called before i18n was initialized"
        return {name: {"status": "running"} for name in names}

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = service_status
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.service_status(["nginx"])

    assert calls == ["init_i18n"]
    assert result == {"fake": False, "services": {"nginx": {"status": "running"}}}


def test_i18n_init_runs_only_once_across_multiple_real_calls(monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []
    yunohost_pkg = types.ModuleType("yunohost")
    yunohost_pkg.init_i18n = lambda: calls.append("init_i18n")
    monkeypatch.setitem(__import__("sys").modules, "yunohost", yunohost_pkg)

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = lambda names, **_: {}
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter.service_status(["nginx"])
    adapter.service_status(["postgresql"])

    assert calls == ["init_i18n"]


def test_missing_top_level_yunohost_package_does_not_crash_i18n_init(monkeypatch: pytest.MonkeyPatch):
    # No "yunohost" entry in sys.modules at all (matches the other adapter
    # tests' sandbox, which inject fake yunohost.* submodules directly
    # without a real top-level package) - _ensure_i18n_initialized must
    # degrade gracefully rather than mis-raising YunohostUnavailableError
    # for the *wrong* module.
    monkeypatch.delitem(__import__("sys").modules, "yunohost", raising=False)

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = lambda names, **_: {n: {"status": "running"} for n in names}
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.service_status(["nginx"])

    assert result == {"fake": False, "services": {"nginx": {"status": "running"}}}
