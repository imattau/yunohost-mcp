"""Fake-mode tests for YunohostAdapter's Phase 14 composite workflows."""

from __future__ import annotations

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter


def make_adapter() -> YunohostAdapter:
    return YunohostAdapter(settings=Settings(fake_yunohost=True))


def test_diagnose_app():
    result = make_adapter().diagnose_app("nextcloud")
    assert result["app"] == "nextcloud"
    assert "app_info" in result
    assert "diagnosis" in result
    assert isinstance(result["related_operations"], list)


def test_validate_server():
    result = make_adapter().validate_server()
    assert "server" in result
    assert "diagnosis" in result
    assert "updates" in result
    assert "services" in result
    assert "backups" in result


def test_http_endpoint_fake_mode_never_makes_a_real_request():
    result = make_adapter().test_http_endpoint("https://example.com/nextcloud")
    assert result["fake"] is True
    assert result["reachable"] is True
    assert result["status_code"] == 200


def test_http_endpoint_real_mode_reports_connection_failure(monkeypatch: pytest.MonkeyPatch):
    import urllib.error

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))

    def fake_urlopen(*args, **kwargs):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = adapter.test_http_endpoint("https://nope.invalid/app")
    assert result["fake"] is False
    assert result["reachable"] is False
    assert result["error"] is not None


def test_http_endpoint_real_mode_treats_http_error_as_reachable(monkeypatch: pytest.MonkeyPatch):
    import urllib.error

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))

    def fake_urlopen(*args, **kwargs):
        raise urllib.error.HTTPError("https://example.com", 503, "Service Unavailable", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = adapter.test_http_endpoint("https://example.com/app")
    assert result["reachable"] is True
    assert result["status_code"] == 503


def test_safe_upgrade_full_cycle_passes():
    result = make_adapter().safe_upgrade("nextcloud")
    assert result["passed"] is True
    step_names = [s["step"] for s in result["steps"]]
    assert step_names == [
        "pre_diagnosis",
        "inspect_app",
        "backup",
        "upgrade",
        "check_app",
        "test_http_endpoint",
        "post_diagnosis",
    ]
    assert result["url_tested"] == "https://example.com/nextcloud"


def test_safe_upgrade_stops_after_backup_failure(monkeypatch: pytest.MonkeyPatch):
    adapter = make_adapter()

    def failing_backup(*args, **kwargs):
        raise RuntimeError("backup failed")

    monkeypatch.setattr(adapter, "backup_create", failing_backup)
    result = adapter.safe_upgrade("nextcloud")
    assert result["passed"] is False
    step_names = [s["step"] for s in result["steps"]]
    assert "upgrade" not in step_names
    assert step_names[-1] == "backup"


def test_repair_app_conservative_restarts_matching_services():
    adapter = make_adapter()
    # Fake services_list() only has "nginx"/"yunohost-api" by default - none
    # contain "nextcloud", so nothing should be restarted for this app.
    result = adapter.repair_app("nextcloud")
    assert result["restarted_services"] == []
    assert result["strategy"] == "conservative"
    assert "diagnosis_before" in result
    assert "diagnosis_after" in result


def test_repair_app_restarts_services_whose_name_matches(monkeypatch: pytest.MonkeyPatch):
    adapter = make_adapter()
    restart_calls = []
    monkeypatch.setattr(
        adapter,
        "services_list",
        lambda: {"fake": True, "services": {"nextcloud": {"status": "failed"}, "nginx": {"status": "running"}}},
    )
    monkeypatch.setattr(adapter, "service_restart", lambda names: restart_calls.append(names))
    result = adapter.repair_app("nextcloud")
    assert result["restarted_services"] == ["nextcloud"]
    assert restart_calls == [["nextcloud"]]


def test_repair_app_rejects_unknown_strategy():
    with pytest.raises(ValueError, match="unknown repair strategy"):
        make_adapter().repair_app("nextcloud", strategy="aggressive")
