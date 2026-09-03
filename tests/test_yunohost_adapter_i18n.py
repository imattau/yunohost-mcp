"""Regression tests: real yunohost.* calls need moulinette bootstrapped.

Several yunohost.* modules reach into moulinette state that's normally set
up by moulinette.cli()/moulinette.api() - the CLI/API bootstrap this
adapter deliberately bypasses by importing yunohost.* directly in-process:

  - yunohost.service (and others) call m18n.key_exists()/m18n.n(), which
    need m18n.translator, unset until yunohost.init_i18n() runs.
  - yunohost.diagnosis's message formatting reads Moulinette.interface.type,
    which is None until a real Cli/Api Interface sets it.

Skipping either raised, respectively:
    AttributeError: 'Moulinette18n' object has no attribute 'translator'
    AttributeError: 'NoneType' object has no attribute 'type'
against a real YunoHost host (caught after fixing a separate
venv-isolation packaging bug that had been masking both).
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


def _install_fake_yunohost_package(monkeypatch: pytest.MonkeyPatch, calls: list[str]) -> None:
    yunohost_pkg = types.ModuleType("yunohost")
    yunohost_pkg.init_i18n = lambda: calls.append("init_i18n")
    monkeypatch.setitem(__import__("sys").modules, "yunohost", yunohost_pkg)


def _install_fake_moulinette_package(monkeypatch: pytest.MonkeyPatch):
    """Reproduces just enough of moulinette.Moulinette for the adapter's
    Moulinette.interface check: a classproperty-like `.interface` reading
    `._interface`, settable via `._interface = ...` exactly like the real
    one (see moulinette/__init__.py's `class Moulinette`)."""

    class _classproperty:
        def __init__(self, f):
            self.f = f

        def __get__(self, obj, owner):
            return self.f(owner)

    class FakeMoulinette:
        _interface = None

        @_classproperty
        def interface(cls):
            return cls._interface

    moulinette_pkg = types.ModuleType("moulinette")
    moulinette_pkg.Moulinette = FakeMoulinette
    monkeypatch.setitem(__import__("sys").modules, "moulinette", moulinette_pkg)
    return FakeMoulinette


def test_real_yunohost_call_initializes_i18n_before_use(monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []
    _install_fake_yunohost_package(monkeypatch, calls)
    _install_fake_moulinette_package(monkeypatch)

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


def test_real_yunohost_call_sets_a_headless_moulinette_interface(monkeypatch: pytest.MonkeyPatch):
    _install_fake_yunohost_package(monkeypatch, [])
    fake_moulinette = _install_fake_moulinette_package(monkeypatch)
    assert fake_moulinette.interface is None

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = lambda names, **_: {}
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter.service_status(["nginx"])

    assert fake_moulinette.interface is not None
    assert fake_moulinette.interface.type == "api"


def test_does_not_override_an_already_set_moulinette_interface(monkeypatch: pytest.MonkeyPatch):
    _install_fake_yunohost_package(monkeypatch, [])
    fake_moulinette = _install_fake_moulinette_package(monkeypatch)

    class _RealInterface:
        type = "cli"

    real_interface = _RealInterface()
    fake_moulinette._interface = real_interface

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = lambda names, **_: {}
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter.service_status(["nginx"])

    assert fake_moulinette.interface is real_interface


def test_i18n_init_runs_only_once_across_multiple_real_calls(monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []
    _install_fake_yunohost_package(monkeypatch, calls)
    _install_fake_moulinette_package(monkeypatch)

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = lambda names, **_: {}
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter.service_status(["nginx"])
    adapter.service_status(["postgresql"])

    assert calls == ["init_i18n"]


def test_missing_top_level_yunohost_and_moulinette_packages_does_not_crash(monkeypatch: pytest.MonkeyPatch):
    # Neither "yunohost" nor "moulinette" in sys.modules (matches the other
    # adapter tests' sandbox, which inject fake yunohost.* submodules
    # directly without real top-level packages) - _ensure_i18n_initialized
    # must degrade gracefully rather than mis-raising YunohostUnavailableError
    # for the *wrong* module.
    monkeypatch.delitem(__import__("sys").modules, "yunohost", raising=False)
    monkeypatch.delitem(__import__("sys").modules, "moulinette", raising=False)

    yunohost_service = types.ModuleType("yunohost.service")
    yunohost_service.service_status = lambda names, **_: {n: {"status": "running"} for n in names}
    monkeypatch.setitem(__import__("sys").modules, "yunohost.service", yunohost_service)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.service_status(["nginx"])

    assert result == {"fake": False, "services": {"nginx": {"status": "running"}}}
