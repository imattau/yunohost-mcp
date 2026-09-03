"""Fake-mode tests for YunohostAdapter's Phase 4 read methods.

fake_yunohost defaults to True (this sandbox has no real yunohost.*
importable), so these exercise the adapter's public contract - method
signatures and the shape of what comes back - without a real YunoHost.
"""

from __future__ import annotations

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter


def make_adapter() -> YunohostAdapter:
    return YunohostAdapter(settings=Settings(fake_yunohost=True))


def test_apps_list():
    result = make_adapter().apps_list()
    assert result["fake"] is True
    assert isinstance(result["apps"], list)


def test_app_info_full_adds_settings():
    adapter = make_adapter()
    basic = adapter.app_info("nextcloud")
    full = adapter.app_info("nextcloud", full=True)
    assert "settings" not in basic
    assert "settings" in full


def test_diagnosis_run_and_get():
    adapter = make_adapter()
    run_result = adapter.diagnosis_run(categories=["ip"])
    assert run_result["categories_run"] == ["ip"]
    get_result = adapter.diagnosis_get()
    assert "categories" in get_result


def test_services_list_and_service_status():
    adapter = make_adapter()
    assert "nginx" in adapter.services_list()["services"]
    status = adapter.service_status(["nginx", "postgresql"])
    assert set(status["services"]) == {"nginx", "postgresql"}


def test_domains_list():
    result = make_adapter().domains_list()
    assert result["main"] in result["domains"]


def test_users_list():
    result = make_adapter().users_list()
    assert "alice" in result["users"]


def test_backups_list():
    result = make_adapter().backups_list()
    assert isinstance(result["archives"], list)


def test_operations_list_status_logs():
    adapter = make_adapter()
    ops = adapter.operations_list()
    assert isinstance(ops["operation"], list)
    status = adapter.operation_status("20260901-120000-app_install")
    assert status["name"] == "20260901-120000-app_install"
    logs = adapter.operation_logs("20260901-120000-app_install")
    assert "log" in logs


def test_updates_check():
    result = make_adapter().updates_check()
    assert isinstance(result["apps"], list)
    assert isinstance(result["system"], list)


def test_service_restart():
    result = make_adapter().service_restart(["nginx", "postgresql"])
    assert result["restarted"] == ["nginx", "postgresql"]


def test_backup_create_has_operation_id():
    result = make_adapter().backup_create(name="my-backup")
    assert result["name"] == "my-backup"
    assert "operation_id" in result


def test_app_install_has_operation_id():
    result = make_adapter().app_install("nextcloud")
    assert result["app"] == "nextcloud"
    assert "operation_id" in result


def test_app_upgrade():
    result = make_adapter().app_upgrade("nextcloud")
    assert result["app"] == "nextcloud"
    assert result["result"] == "success"
