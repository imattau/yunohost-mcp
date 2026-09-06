"""Fake-mode tests for YunohostAdapter's Phase 4 read methods.

fake_yunohost defaults to True (this sandbox has no real yunohost.*
importable), so these exercise the adapter's public contract - method
signatures and the shape of what comes back - without a real YunoHost.
"""

from __future__ import annotations

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.polypack import PolypackUnavailableError
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostAdapter, YunohostUnavailableError


def make_adapter() -> YunohostAdapter:
    return YunohostAdapter(settings=Settings(fake_yunohost=True))


def test_broker_mode_fails_closed_for_unregistered_adapter_operations(tmp_path, monkeypatch):
    # A synthetic, definitely-unregistered method name - test_http_endpoint
    # itself used to be the example here, but it's a real (if internal-only)
    # method that belongs in _BROKERED_METHODS (see the regression test
    # below), so asserting it's guarded was actually pinning a bug.
    monkeypatch.setattr(YunohostAdapter, "not_a_real_operation", lambda self: None, raising=False)
    adapter = YunohostAdapter(settings=Settings(broker_socket_path=tmp_path / "broker.sock"))

    with pytest.raises(YunohostUnavailableError, match="not yet available through the privileged broker"):
        adapter.not_a_real_operation()


def test_broker_mode_does_not_guard_test_http_endpoint(tmp_path):
    """Regression test: test_http_endpoint isn't its own MCP tool, but
    safe_upgrade() (itself brokered) calls self.test_http_endpoint(...) as
    an internal step - __post_init__'s per-instance guard shadows that call
    too if the method's own name is missing from _BROKERED_METHODS, which
    silently turned safe_upgrade's post-upgrade HTTP check into a
    guaranteed failure under broker mode (caught and reported as a failed
    step, not a crash - easy to miss). Found alongside the settings/
    regenconf/dns/etc. omissions this test file's completeness test below
    now guards against."""
    adapter = YunohostAdapter(settings=Settings(broker_socket_path=tmp_path / "broker.sock", fake_yunohost=True))

    result = adapter.test_http_endpoint("https://example.test")
    assert result["fake"] is True


def test_brokered_methods_covers_every_public_adapter_method():
    """Completeness check for _BROKERED_METHODS itself - regression test
    for the bug class this session found live: settings_list, settings_get,
    settings_set, regenconf_pending, regenconf_apply, domain_dns_suggest,
    domain_dns_push_preview, domain_dns_push, domain_remove,
    user_permission_info, user_permission_update, backup_info,
    system_reboot, system_shutdown, and test_http_endpoint were all added
    as adapter methods without ever being added to this allowlist, so every
    one of them failed with "not yet available through the privileged
    broker" on both real deployments despite being fully implemented,
    tested (in fake mode), and documented. Fake-mode tests never catch this
    because they never construct an adapter with broker_socket_path set.
    """
    import inspect

    public_methods = {
        name
        for name, _ in inspect.getmembers(YunohostAdapter, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    missing = sorted(public_methods - YunohostAdapter._BROKERED_METHODS)
    assert missing == [], f"adapter methods missing from _BROKERED_METHODS: {missing}"


def test_broker_mode_does_not_guard_the_polypack_memory_methods(tmp_path):
    """Regression test: memory_* proxies to Polypack over loopback HTTP and
    never touches root-privileged YunoHost operations, so broker mode must
    not block it behind the "not yet available through the privileged
    broker" guard the way it blocks unregistered YunoHost operations.
    Before the fix, memory_* wasn't in _BROKERED_METHODS and every call
    failed with that guard error regardless of Polypack configuration."""
    adapter = YunohostAdapter(settings=Settings(broker_socket_path=tmp_path / "broker.sock"))

    with pytest.raises(PolypackUnavailableError, match="Polypack integration is not configured"):
        adapter.memory_list_contexts()


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


def test_app_setting_get_fake_mode():
    result = make_adapter().app_setting_get("nextcloud", "install_dir")
    assert result == {"fake": True, "app": "nextcloud", "key": "install_dir", "value": None}


def test_app_setting_set_fake_mode():
    result = make_adapter().app_setting_set("nextcloud", "install_dir", value="/var/www/nextcloud")
    assert result == {
        "fake": True,
        "app": "nextcloud",
        "key": "install_dir",
        "value": "/var/www/nextcloud",
        "deleted": False,
    }
    assert "operation_id" not in result


def test_app_setting_set_delete_fake_mode():
    result = make_adapter().app_setting_set("nextcloud", "stale_key", delete=True)
    assert result == {"fake": True, "app": "nextcloud", "key": "stale_key", "value": None, "deleted": True}


def test_app_setting_set_requires_exactly_one_of_value_or_delete():
    with pytest.raises(ValueError):
        make_adapter().app_setting_set("nextcloud", "install_dir")
    with pytest.raises(ValueError):
        make_adapter().app_setting_set("nextcloud", "install_dir", value="x", delete=True)


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


def test_introspection_tools_have_fake_contracts():
    adapter = make_adapter()
    assert adapter.journal_query(["kernel"])["fake"] is True
    assert adapter.web_logs(status=500)["fake"] is True
    assert adapter.system_snapshot()["fake"] is True
    assert adapter.service_history(["nginx"])["fake"] is True
    assert adapter.ssh_diagnose()["fake"] is True
    assert adapter.network_snapshot()["fake"] is True
    assert adapter.http_probe("https://example.test")["fake"] is True
    assert adapter.incident_snapshot(lines=10)["fake"] is True


def test_web_logs_parses_access_and_error_records(tmp_path):
    (tmp_path / "access.log").write_text(
        '203.0.113.10 - - [06/Sep/2026:10:00:00 +0000] \"GET /broken HTTP/1.1\" 500 123 \"-\" \"test-agent\" 502 127.0.0.1:9000\\n'
    )
    (tmp_path / "error.log").write_text(
        '2026/09/06 10:00:01 [error] 123#123: *1 upstream timed out, client: 203.0.113.10\\n'
    )
    adapter = YunohostAdapter(
        settings=Settings(fake_yunohost=False, nginx_log_dir=tmp_path)
    )

    result = adapter.web_logs(since="2026-09-06T09:59:00Z", until="2026-09-06T10:01:00Z")

    assert len(result["entries"]) == 2
    entry = next(item for item in result["entries"] if item["kind"] == "access")
    assert entry["kind"] == "access"
    assert entry["path"] == "/broken"
    assert entry["status"] == 500
    assert entry["upstream_status"] == 502
    assert entry["upstream_address"] == "127.0.0.1:9000"
    error = next(item for item in result["entries"] if item["kind"] == "error")
    assert "upstream timed out" in error["message"]


def test_journal_query_kernel_unit_passes_dash_k_as_a_bare_flag(monkeypatch):
    """-k/--dmesg takes no value; passing the unit name after it makes
    journalctl try to parse "kernel" as a match expression and fail with
    "Failed to add match 'kernel': Invalid argument"."""
    captured_args: list[str] = []

    class FakeCompletedProcess:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(args, **kwargs):
        captured_args.extend(args)
        return FakeCompletedProcess()

    monkeypatch.setattr("yunohost_mcp.yunohost.adapter.subprocess.run", fake_run)
    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))

    adapter.journal_query(["kernel"])

    assert "-k" in captured_args
    k_index = captured_args.index("-k")
    assert k_index == len(captured_args) - 1 or captured_args[k_index + 1] != "kernel"


def test_http_probe_reaches_the_real_network_path_without_crashing(monkeypatch):
    """Regression for a NameError: name 'time' is not defined - http_probe's
    elapsed-time tracking used the `time` module without importing it, so
    every non-fake probe of a public URL crashed before making a request."""

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def read(self, _n):
            return b""

        def geturl(self):
            return "https://example.test/"

    monkeypatch.setattr(
        "yunohost_mcp.yunohost.adapter.urllib.request.urlopen", lambda *a, **k: FakeResponse()
    )
    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False, allow_private_http_probes=True))

    result = adapter.http_probe("https://example.test")

    assert result["reachable"] is True
    assert result["status_code"] == 200
    assert isinstance(result["elapsed_ms"], float)


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


def test_domain_cert_install_reports_the_silent_acme_readiness_skip(monkeypatch):
    """Regression: yunohost.certificate._certificate_install_letsencrypt()
    catches _check_domain_is_ready_for_ACME() failures with `except
    Exception: logger.error(e); continue` - it never adds the domain to
    failed_cert_install, so certificate_install() returns normally with NO
    exception at all (it only raises when failed_cert_install is
    non-empty). Confirmed live against a freshly domain_add'd nohost.me
    subdomain: two consecutive real domain_cert_install calls each came
    back acme_error=None with the certificate still selfsigned, while the
    root helper's own log carried "There is no diagnosis result for domain
    ... yet" both times. Before this fix, that silent no-op was reported
    to the caller as an unqualified success."""

    def fake_import_attr(module_name: str, attr: str):
        if (module_name, attr) == ("yunohost.certificate", "certificate_install"):
            # The real function under this exact failure mode: it runs to
            # completion and returns None, having merely logged the
            # readiness-check failure and skipped the domain.
            return lambda domains, **kwargs: None
        if (module_name, attr) == ("yunohost.utils.error", "YunohostError"):
            return Exception
        if (module_name, attr) == ("yunohost.certificate", "certificate_status"):
            return lambda domains, full=False: {
                "certificates": {domains[0]: {"CA_type": "selfsigned", "summary": "selfsigned"}}
            }
        raise AssertionError(f"unexpected _import_attr({module_name!r}, {attr!r})")

    monkeypatch.setattr("yunohost_mcp.yunohost.adapter._import_attr", fake_import_attr)
    monkeypatch.setattr("yunohost_mcp.yunohost.adapter._latest_operation_id", lambda: "op-1")

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.domain_cert_install("clips.example.com")

    assert result["certificate"]["CA_type"] == "selfsigned"
    assert result["acme_error"] is not None
    assert "diagnosis" in result["acme_error"]


def test_domain_cert_install_selfsigned_request_is_not_flagged_as_a_skip(monkeypatch):
    """The new post-hoc check must only fire when letsencrypt was actually
    requested - a deliberate self-signed install ending up selfsigned is
    the expected, successful outcome, not a silent-skip false positive."""

    def fake_import_attr(module_name: str, attr: str):
        if (module_name, attr) == ("yunohost.certificate", "certificate_install"):
            return lambda domains, **kwargs: None
        if (module_name, attr) == ("yunohost.utils.error", "YunohostError"):
            return Exception
        if (module_name, attr) == ("yunohost.certificate", "certificate_status"):
            return lambda domains, full=False: {
                "certificates": {domains[0]: {"CA_type": "selfsigned", "summary": "selfsigned"}}
            }
        raise AssertionError(f"unexpected _import_attr({module_name!r}, {attr!r})")

    monkeypatch.setattr("yunohost_mcp.yunohost.adapter._import_attr", fake_import_attr)
    monkeypatch.setattr("yunohost_mcp.yunohost.adapter._latest_operation_id", lambda: "op-1")

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.domain_cert_install("clips.example.com", letsencrypt=False)

    assert result["certificate"]["CA_type"] == "selfsigned"
    assert result["acme_error"] is None


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


def test_service_stop():
    result = make_adapter().service_stop(["nginx", "postgresql"])
    assert result["stopped"] == ["nginx", "postgresql"]


def test_service_start():
    result = make_adapter().service_start(["nginx", "postgresql"])
    assert result["started"] == ["nginx", "postgresql"]


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
