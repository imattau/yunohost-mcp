"""Regression tests for _call_via_system_python and the backup_create/
backup_restore/package_inspect rewiring onto it.

backup_create/backup_restore transitively import yunohost.utils.form (via
backup's storage-location settings, or directly via app_manifest() for
package_inspect), which defines pydantic models using
pydantic v1's @validator(field=..., config=...) signature - only valid
against the actual pydantic v1 Debian's apt-installed python3-pydantic
provides. This venv installs its own newer pydantic v2 (required by the
mcp SDK and this server's own models), which shadows the system one for
any *in-process* import of yunohost.utils.form, crashing with:
    PydanticUserError: The `field` and `config` parameters are not
    available in Pydantic V2, please use the `info` parameter instead.
Since a process can only ever have one `pydantic` module loaded (Python
caches imports in sys.modules; nothing later can make a plain `import
pydantic` elsewhere in the same process see v1 once v2 is already loaded),
in-process coexistence of both versions is impossible - caught against a
real YunoHost host after fixing the three earlier moulinette-bootstrap
bugs had gotten backup_create just far enough to hit it.

_call_via_system_python sidesteps this by running the real yunohost.*
call in a subprocess using the *system* python3, which never sees this
venv's site-packages (and therefore its pydantic v2) at all.
"""

from __future__ import annotations

import sys

import pytest

import yunohost_mcp.yunohost.adapter as adapter_module
from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter, YunohostUnavailableError, _call_via_system_python


def _settings(**overrides) -> Settings:
    return Settings(fake_yunohost=False, system_python=sys.executable, system_python_timeout_seconds=30, **overrides)


def test_call_via_system_python_round_trips_kwargs_through_a_real_subprocess():
    # builtins.dict(**kwargs) just echoes kwargs back as a dict - a real
    # subprocess round trip (JSON out, spawn, bootstrap best-effort import
    # of yunohost/moulinette which aren't installed in this dev sandbox
    # and must be swallowed harmlessly, JSON back) without needing a real
    # YunoHost host.
    result = _call_via_system_python("builtins", "dict", {"a": 1, "b": "x", "c": None}, _settings())
    assert result == {"a": 1, "b": "x", "c": None}


def test_call_via_system_python_wraps_a_subprocess_crash():
    with pytest.raises(YunohostUnavailableError, match="totally_not_a_real_module_xyz"):
        _call_via_system_python("totally_not_a_real_module_xyz", "whatever", {}, _settings())


def test_call_via_system_python_reports_nonzero_exit_and_stderr():
    with pytest.raises(YunohostUnavailableError, match="failed in the system-python subprocess"):
        _call_via_system_python("totally_not_a_real_module_xyz", "whatever", {}, _settings())


def test_backup_create_calls_call_via_system_python_with_correct_kwargs(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return {"name": "my-backup", "size": 123, "results": {}}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)
    monkeypatch.setattr(adapter_module, "_latest_operation_id", lambda: "20260903-000000-backup_create")

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.backup_create(name="my-backup", apps=["nextcloud"])

    assert captured["module_name"] == "yunohost.backup"
    assert captured["attr"] == "backup_create"
    assert captured["kwargs"] == {"name": "my-backup", "description": None, "apps": ["nextcloud"], "system": []}
    assert result == {
        "fake": False,
        "operation_id": "20260903-000000-backup_create",
        "name": "my-backup",
        "result": {"name": "my-backup", "size": 123, "results": {}},
    }


def test_backup_restore_calls_call_via_system_python_with_correct_kwargs(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.backup_restore("20260901-000000", apps=["nextcloud"])

    assert captured["module_name"] == "yunohost.backup"
    assert captured["attr"] == "backup_restore"
    assert captured["kwargs"] == {"name": "20260901-000000", "system": [], "apps": ["nextcloud"], "force": False}
    assert result == {"fake": False, "name": "20260901-000000", "result": None}


def test_app_install_calls_call_via_system_python_with_correct_kwargs(monkeypatch: pytest.MonkeyPatch):
    # app_install() re-parses the target manifest's [install] options,
    # which for any domain/group question hits the same DomainOption/
    # GroupOption pydantic v1/v2 conflict as backup_create/backup_restore/
    # package_inspect above.
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return {"notifications": {}}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)
    monkeypatch.setattr(adapter_module, "_latest_operation_id", lambda: "20260903-000000-app_install")

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.app_install("ditto", label="Ditto")

    assert captured["module_name"] == "yunohost.app"
    assert captured["attr"] == "app_install"
    assert captured["kwargs"] == {"app": "ditto", "label": "Ditto", "args": None, "force": False}
    assert result == {
        "fake": False,
        "operation_id": "20260903-000000-app_install",
        "result": {"notifications": {}},
    }


def test_app_upgrade_calls_call_via_system_python_with_correct_kwargs(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return {"success": ["ditto"]}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.app_upgrade(app="ditto", file="/tmp/ditto-candidate")

    assert captured["module_name"] == "yunohost.app"
    assert captured["attr"] == "app_upgrade"
    assert captured["kwargs"] == {"app": "ditto", "force": False, "file": "/tmp/ditto-candidate", "url": None}
    assert result == {"fake": False, "app": "ditto", "result": {"success": ["ditto"]}}


def test_users_list_calls_system_python(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured.update(module_name=module_name, attr=attr, kwargs=kwargs)
        return {"users": {"codex": {"fullname": "Codex"}}}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)

    result = YunohostAdapter(settings=_settings()).users_list()

    assert captured == {"module_name": "yunohost.user", "attr": "user_list", "kwargs": {}}
    assert result == {"fake": False, "users": {"codex": {"fullname": "Codex"}}}


def test_app_upgrade_passes_url_for_a_non_catalog_app(monkeypatch: pytest.MonkeyPatch):
    # An app installed directly from a Git URL (never registered in any
    # catalog - e.g. this server's own yunohost_mcp app) has no catalog
    # entry for app_upgrade() to diff against without an explicit `url`,
    # and fails with "No apps can be upgraded" otherwise - caught live
    # trying to self-upgrade yunohost_mcp via the MCP tool.
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["kwargs"] = kwargs
        return {"success": ["yunohost_mcp"]}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)

    adapter = YunohostAdapter(settings=_settings())
    adapter.app_upgrade(app="yunohost_mcp", url="https://github.com/imattau/yunohost-mcp_ynh")

    assert captured["kwargs"] == {
        "app": "yunohost_mcp",
        "force": False,
        "file": None,
        "url": "https://github.com/imattau/yunohost-mcp_ynh",
    }


def test_app_upgrade_reports_nothing_to_upgrade_cleanly(monkeypatch: pytest.MonkeyPatch):
    def no_upgrade(*args, **kwargs):
        raise adapter_module.YunohostUnavailableError(
            "yunohost.app.app_upgrade failed in the system-python subprocess "
            "(exit 1): No apps can be upgraded"
        )

    monkeypatch.setattr(adapter_module, "_call_via_system_python", no_upgrade)

    adapter = YunohostAdapter(settings=_settings())
    with pytest.raises(adapter_module.NoAppsToUpgradeError, match="nothing to upgrade"):
        adapter.app_upgrade(app="yunohost_mcp")


def test_domain_add_calls_call_via_system_python_with_correct_kwargs_and_always_ignores_dyndns(
    monkeypatch: pytest.MonkeyPatch,
):
    # domain_add() re-parses the same DomainOption/GroupOption manifest
    # machinery app_install does, hitting the same pydantic v1/v2 conflict.
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return None

    def fake_certificate_status(domains):
        return {"certificates": {d: {"CA_type": "selfsigned"} for d in domains}}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)
    monkeypatch.setattr(adapter_module, "_latest_operation_id", lambda: "20260903-000000-domain_add")
    monkeypatch.setattr(adapter_module, "_import_attr", lambda module, attr: fake_certificate_status)

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.domain_add("new-app.example.nohost.me", install_letsencrypt_cert=True)

    assert captured["module_name"] == "yunohost.domain"
    assert captured["attr"] == "domain_add"
    assert captured["kwargs"] == {
        "domain": "new-app.example.nohost.me",
        "ignore_dyndns": True,
        "install_letsencrypt_cert": True,
    }
    assert result == {
        "fake": False,
        "operation_id": "20260903-000000-domain_add",
        "domain": "new-app.example.nohost.me",
        "certificate": {"CA_type": "selfsigned"},
    }


def test_app_change_url_calls_call_via_system_python_with_correct_kwargs(monkeypatch: pytest.MonkeyPatch):
    # app_change_url() imports yunohost.utils.form (DomainOption,
    # WebPathOption) to normalize/validate the new domain and path - same
    # pydantic v1/v2 conflict as app_install/domain_add above.
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return None  # app_change_url() itself returns None on success

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)
    monkeypatch.setattr(adapter_module, "_latest_operation_id", lambda: "20260903-000000-app_change_url")

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.app_change_url("mangatsu", domain="manga.example.com", path="/")

    assert captured["module_name"] == "yunohost.app"
    assert captured["attr"] == "app_change_url"
    assert captured["kwargs"] == {"app": "mangatsu", "domain": "manga.example.com", "path": "/"}
    assert result == {
        "fake": False,
        "operation_id": "20260903-000000-app_change_url",
        "app": "mangatsu",
        "domain": "manga.example.com",
        "path": "/",
    }


def test_package_inspect_calls_call_via_system_python_with_correct_kwargs(monkeypatch: pytest.MonkeyPatch):
    # app_manifest() imports yunohost.utils.form (for its "install"
    # questions field) - same pydantic v1/v2 conflict as backup_create/
    # backup_restore, previously unnoticed because package_inspect had no
    # test exercising its real-mode path at all.
    captured = {}

    def fake_call(module_name, attr, kwargs, settings):
        captured["module_name"] = module_name
        captured["attr"] = attr
        captured["kwargs"] = kwargs
        return {"id": "my_webapp", "resources": {"permissions": {}}}

    monkeypatch.setattr(adapter_module, "_call_via_system_python", fake_call)

    adapter = YunohostAdapter(settings=_settings())
    result = adapter.package_inspect("my_webapp")

    assert captured["module_name"] == "yunohost.app"
    assert captured["attr"] == "app_manifest"
    assert captured["kwargs"] == {"app": "my_webapp"}
    assert result["id"] == "my_webapp"
    assert result["fake"] is False
