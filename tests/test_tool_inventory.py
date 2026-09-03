"""Keep the public MCP tool surface aligned with the recorded roadmap."""

import ast
from pathlib import Path


EXPECTED_TOOLS = frozenset(
    {
        "server_info",
        "health_check",
        "apps_list",
        "app_info",
        "app_resources",
        "diagnosis_run",
        "diagnosis_get",
        "services_list",
        "service_status",
        "service_logs",
        "domains_list",
        "users_list",
        "backups_list",
        "operations_list",
        "operation_status",
        "operation_logs",
        "updates_check",
        "service_restart",
        "backup_create",
        "app_install",
        "app_upgrade",
        "plan_app_upgrade",
        "execute_plan",
        "app_remove",
        "backup_restore",
        "system_upgrade",
        "package_inspect",
        "package_lint",
        "package_install_test",
        "package_upgrade_test",
        "package_backup_test",
        "package_restore_test",
        "package_change_url_test",
        "package_remove_test",
        "package_logs",
        "package_run_tests",
        "audit_list",
        "audit_get",
        "approve_operation",
        "diagnose_app",
        "validate_server",
        "safe_upgrade",
        "repair_app",
        "test_package",
        "catalog_package_inspect",
        "catalog_publish_plan",
        "catalog_verify",
        "catalog_publish",
        "whoami",
        "server_identity",
    }
)


def _registered_tools() -> frozenset[str]:
    server_path = Path(__file__).parents[1] / "src" / "yunohost_mcp" / "server.py"
    tree = ast.parse(server_path.read_text())
    tools = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "mcp"
            and decorator.func.attr == "tool"
            for decorator in node.decorator_list
        ):
            tools.add(node.name)
    return frozenset(tools)


def test_registered_tools_match_roadmap_inventory() -> None:
    actual = _registered_tools()
    assert actual == EXPECTED_TOOLS, {
        "missing": sorted(EXPECTED_TOOLS - actual),
        "unexpected": sorted(actual - EXPECTED_TOOLS),
    }
