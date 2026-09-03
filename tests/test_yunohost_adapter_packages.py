"""Fake-mode tests for YunohostAdapter's Phase 8 package-development methods."""

from __future__ import annotations

from pathlib import Path

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter

# A real checkout of github.com/YunoHost/package_linter, present on this dev
# box (see PHASE0_INVESTIGATION.md-style discovery) - not something every
# environment running this test suite will have, so tests using it skip
# cleanly rather than failing when it's absent.
REAL_LINTER_PATH = Path("/tmp/yunohost-package-linter")
REAL_LINTER_PYTHON = "/usr/bin/python3"
REAL_APP_TO_LINT = Path(__file__).resolve().parents[2] / "blossom_ynh"


def make_adapter() -> YunohostAdapter:
    return YunohostAdapter(settings=Settings(fake_yunohost=True))


def test_package_inspect():
    result = make_adapter().package_inspect("/path/to/example_ynh")
    assert result["fake"] is True
    assert "resources" in result
    assert result["unknown_resource_types"] == []


def test_package_lint_fake_mode():
    result = make_adapter().package_lint("/path/to/example_ynh")
    assert result["fake"] is True
    assert result["passed"] is True


def test_package_lint_unavailable_without_linter_path():
    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.package_lint("/path/to/example_ynh")
    assert result["unavailable"] is True


def test_package_install_test():
    result = make_adapter().package_install_test("/path/to/example_ynh", label="Test App")
    assert result["app"] == "/path/to/example_ynh"
    assert "operation_id" in result


def test_package_upgrade_test():
    result = make_adapter().package_upgrade_test("example", "/path/to/example_ynh")
    assert result["app"] == "example"
    assert result["file"] == "/path/to/example_ynh"


def test_package_backup_test():
    result = make_adapter().package_backup_test("example")
    assert result["name"] == "package-test-example"


def test_package_restore_test():
    result = make_adapter().package_restore_test("example", "package-test-example")
    assert result["name"] == "package-test-example"
    assert result["apps"] == ["example"]


def test_package_change_url_test():
    result = make_adapter().package_change_url_test("example", "new.example.com", "/")
    assert result["app"] == "example"
    assert "operation_id" in result


def test_package_remove_test_purges_by_default():
    result = make_adapter().package_remove_test("example")
    assert result["purged"] is True


def test_package_run_tests_full_cycle_passes():
    result = make_adapter().package_run_tests("/path/to/example_ynh")
    assert result["passed"] is True
    step_names = [s["step"] for s in result["steps"]]
    assert step_names == ["install", "backup", "remove", "restore", "cleanup_remove"]
    assert all(s["passed"] for s in result["steps"])


def test_package_run_tests_uses_explicit_app_id_over_manifest_id():
    adapter = make_adapter()
    result = adapter.package_run_tests("/path/to/example_ynh", app_id="my-custom-id")
    backup_step = next(s for s in result["steps"] if s["step"] == "backup")
    assert backup_step["result"]["name"] == "package-test-my-custom-id"


def test_package_run_tests_stops_after_install_failure(monkeypatch: pytest.MonkeyPatch):
    adapter = make_adapter()

    def failing_install(*args, **kwargs):
        raise RuntimeError("install script failed")

    monkeypatch.setattr(adapter, "package_install_test", failing_install)
    result = adapter.package_run_tests("/path/to/example_ynh")
    assert result["passed"] is False
    assert result["steps"] == [{"step": "install", "passed": False, "error": "install script failed"}]


def test_package_run_tests_stops_after_backup_failure(monkeypatch: pytest.MonkeyPatch):
    adapter = make_adapter()

    def failing_backup(*args, **kwargs):
        raise RuntimeError("backup script failed")

    monkeypatch.setattr(adapter, "package_backup_test", failing_backup)
    result = adapter.package_run_tests("/path/to/example_ynh")
    assert result["passed"] is False
    step_names = [s["step"] for s in result["steps"]]
    # remove and cleanup still run (install already happened), but restore
    # never does since it depends on a successful backup.
    assert "restore" not in step_names
    assert "cleanup_remove" not in step_names
    backup_step = next(s for s in result["steps"] if s["step"] == "backup")
    assert backup_step["passed"] is False


@pytest.mark.skipif(
    not REAL_LINTER_PATH.exists() or not REAL_APP_TO_LINT.exists(),
    reason="requires a local package_linter checkout and a real _ynh app to lint",
)
def test_package_lint_against_real_linter_and_real_app():
    """Real subprocess call to the actual upstream package_linter, against
    a real YunoHost app package - not fake_yunohost, not a stand-in. Proves
    the subprocess wiring (interpreter, cwd, --json parsing) actually works,
    not just that the fake branch returns plausible-looking data."""
    settings = Settings(
        fake_yunohost=False,
        package_linter_path=REAL_LINTER_PATH,
        package_linter_python=REAL_LINTER_PYTHON,
    )
    adapter = YunohostAdapter(settings=settings)
    result = adapter.package_lint(str(REAL_APP_TO_LINT))

    assert result["fake"] is False
    assert isinstance(result["passed"], bool)
    for severity in ("success", "info", "warning", "error", "critical"):
        assert isinstance(result[severity], list)
    # Real, specific findings we already confirmed by running it manually -
    # pins the test to actual linter output, not just "some list came back".
    assert "AppCatalog.is_in_catalog" in result["critical"]
