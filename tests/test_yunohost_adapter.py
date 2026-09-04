"""Fake-mode tests for YunohostAdapter's Phase 4 read methods.

fake_yunohost defaults to True (this sandbox has no real yunohost.*
importable), so these exercise the adapter's public contract - method
signatures and the shape of what comes back - without a real YunoHost.
"""

from __future__ import annotations

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostAdapter


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


def test_app_resources_returns_declared_resources():
    result = make_adapter().app_resources("nextcloud")
    assert result["fake"] is True
    assert result["app"] == "nextcloud"
    assert isinstance(result["resources"], dict)


def test_app_config_get_fake_mode():
    result = make_adapter().app_config_get("quantumrelay", key="peer_mesh.mesh.peers", full=True)
    assert result["fake"] is True
    assert result["app"] == "quantumrelay"
    assert result["key"] == "peer_mesh.mesh.peers"
    assert result["config"] == {}


def test_app_config_set_has_operation_id():
    result = make_adapter().app_config_set("quantumrelay", key="peer_mesh.mesh.peers", value="wss://qr.3nostr.com:8443")
    assert result["fake"] is True
    assert result["app"] == "quantumrelay"
    assert result["key"] == "peer_mesh.mesh.peers"
    assert result["value"] == "wss://qr.3nostr.com:8443"
    assert "operation_id" in result


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


def test_domain_add_defaults_to_a_selfsigned_certificate():
    result = make_adapter().domain_add("new.example.com")
    assert result["fake"] is True
    assert result["domain"] == "new.example.com"
    assert result["certificate"]["CA_type"] == "selfsigned"


def test_domain_add_reports_letsencrypt_when_requested():
    result = make_adapter().domain_add("new.example.com", install_letsencrypt_cert=True)
    assert result["certificate"]["CA_type"] == "letsencrypt"


def test_domain_cert_info():
    result = make_adapter().domain_cert_info("example.com")
    assert result["fake"] is True
    assert result["domain"] == "example.com"
    assert "CA_type" in result["certificate"]


def test_domain_cert_install_defaults_to_letsencrypt():
    result = make_adapter().domain_cert_install("example.com")
    assert result["fake"] is True
    assert result["requested"] == "letsencrypt"
    assert result["acme_error"] is None
    assert result["certificate"]["CA_type"] == "letsencrypt"


def test_domain_cert_install_can_request_selfsigned():
    result = make_adapter().domain_cert_install("example.com", letsencrypt=False)
    assert result["requested"] == "selfsigned"
    assert result["certificate"]["CA_type"] == "selfsigned"


def test_domain_cert_install_rejects_staging():
    with pytest.raises(ToolInputError):
        make_adapter().domain_cert_install("example.com", staging=True)


def test_free_space_bytes_reports_a_large_fake_figure_regardless_of_real_disk():
    # fake_yunohost must never touch the real filesystem of whatever
    # machine happens to be running this process - a disk-constrained CI
    # runner/dev container shouldn't make a fake-mode call see a low
    # figure that a real YunoHost server's own diagnosis would never report.
    assert make_adapter().free_space_bytes() >= 10 * 1000**3


def test_users_list():
    result = make_adapter().users_list()
    assert "alice" in result["users"]


def test_user_create():
    result = make_adapter().user_create("alice", domain="example.com", password="hunter2", fullname="Alice Example")
    assert result["fake"] is True
    assert result["username"] == "alice"


def test_user_update():
    result = make_adapter().user_update("alice", fullname="Alice New")
    assert result["fake"] is True
    assert result["username"] == "alice"


def test_user_delete():
    result = make_adapter().user_delete("alice", purge=True)
    assert result["fake"] is True
    assert result["username"] == "alice"


def test_user_group_list():
    result = make_adapter().user_group_list()
    assert "all_users" in result["groups"]


def test_user_group_create():
    result = make_adapter().user_group_create("editors")
    assert result["fake"] is True
    assert result["groupname"] == "editors"


def test_user_group_update():
    result = make_adapter().user_group_update("editors", add=["alice"])
    assert result["fake"] is True
    assert result["groupname"] == "editors"


def test_user_group_delete():
    result = make_adapter().user_group_delete("editors")
    assert result["fake"] is True
    assert result["groupname"] == "editors"


def test_user_permission_list():
    result = make_adapter().user_permission_list()
    assert "permissions" in result


def test_user_permission_add():
    result = make_adapter().user_permission_add("myapp.main", ["alice"])
    assert result["fake"] is True
    assert result["permission"] == "myapp.main"
    assert result["names"] == ["alice"]


def test_user_permission_remove():
    result = make_adapter().user_permission_remove("myapp.main", ["alice"])
    assert result["fake"] is True
    assert result["permission"] == "myapp.main"
    assert result["names"] == ["alice"]


def test_backups_list():
    result = make_adapter().backups_list()
    assert isinstance(result["archives"], list)


def test_backup_created_at_times():
    result = make_adapter().backup_created_at_times()
    assert isinstance(result, dict)
    assert all(isinstance(v, float) for v in result.values())


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


def test_updates_refresh_defaults_to_apps_target():
    result = make_adapter().updates_refresh()
    assert result["fake"] is True
    assert result["target"] == "apps"
    assert isinstance(result["apps"], list)
    assert isinstance(result["system"], list)


def test_updates_refresh_accepts_system_and_all_targets():
    adapter = make_adapter()
    assert adapter.updates_refresh(target="system")["target"] == "system"
    assert adapter.updates_refresh(target="all")["target"] == "all"


def test_updates_refresh_rejects_an_unknown_target():
    with pytest.raises(ToolInputError):
        make_adapter().updates_refresh(target="bogus")


def test_plan_app_upgrade_matches_updates_check():
    result = make_adapter().plan_app_upgrade("nextcloud")
    assert result["app"] == "nextcloud"
    assert result["upgradable"] is True
    assert result["current_version"] == "28.0.1~ynh1"
    assert result["target_version"] == "28.0.2~ynh1"


def test_plan_app_upgrade_for_non_upgradable_app():
    result = make_adapter().plan_app_upgrade("some-other-app")
    assert result["upgradable"] is False
    assert result["current_version"] is None
    assert result["target_version"] is None


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


def test_app_remove_has_operation_id():
    result = make_adapter().app_remove("nextcloud", purge=True)
    assert result["app"] == "nextcloud"
    assert result["purged"] is True
    assert "operation_id" in result


def test_app_change_url_has_operation_id():
    result = make_adapter().app_change_url("nextcloud", domain="new.example.com", path="/cloud")
    assert result["app"] == "nextcloud"
    assert result["domain"] == "new.example.com"
    assert result["path"] == "/cloud"
    assert "operation_id" in result


def test_backup_restore():
    result = make_adapter().backup_restore("20260901-000000", apps=["nextcloud"])
    assert result["name"] == "20260901-000000"
    assert result["apps"] == ["nextcloud"]


def test_system_upgrade_has_operation_id():
    result = make_adapter().system_upgrade()
    assert "operation_id" in result
    assert result["result"] == "success"


def test_migrations_list():
    result = make_adapter().migrations_list(pending=True)
    assert result["migrations"] == []


def test_migrations_state():
    result = make_adapter().migrations_state()
    assert result["migrations"] == {}


def test_migrations_run():
    result = make_adapter().migrations_run(targets=["0027_migrate_to_bookworm"])
    assert result["targets"] == ["0027_migrate_to_bookworm"]
    assert "state" in result


def test_firewall_list():
    result = make_adapter().firewall_list(protocol="tcp")
    assert result["tcp"] == []


def test_firewall_is_open():
    result = make_adapter().firewall_is_open(443, "tcp")
    assert result["port"] == 443
    assert result["protocol"] == "tcp"
    assert result["open"] is False


def test_firewall_open():
    result = make_adapter().firewall_open(8080, "tcp", comment="test")
    assert result["port"] == 8080
    assert result["protocol"] == "tcp"


def test_firewall_close():
    result = make_adapter().firewall_close(8080, "tcp")
    assert result["port"] == 8080
    assert result["protocol"] == "tcp"


def test_firewall_reload():
    result = make_adapter().firewall_reload()
    assert result["reloaded"] is True
