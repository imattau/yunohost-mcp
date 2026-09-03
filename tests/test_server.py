"""End-to-end smoke test: a real MCP client session against yunohost_mcp.server.

Uses the MCP SDK's in-process `Client` (backed by `InMemoryTransport`) so this
exercises the actual MCP protocol (tool listing, tool call, JSON-RPC framing)
rather than just calling the underlying Python functions directly.

This exercises the stdio-equivalent path, which is implicitly fully
trusted (see auth/identity.py's LOCAL_STDIO_REQUEST) — so tests set that
context themselves, the way server.py's stdio branch of main() does.
"""

from __future__ import annotations

import json

import pytest
from mcp.client import Client

from yunohost_mcp.auth.identity import AuthenticatedRequest, IdentityRecord, LOCAL_STDIO_REQUEST, set_current_request
from yunohost_mcp.policy.roles import scopes_for_roles
from yunohost_mcp.server import audit_log, mcp

PHASE5_WRITE_TOOLS = {"service_restart", "backup_create", "app_install", "app_upgrade"}
PHASE6_WRITE_TOOLS = {"app_remove", "backup_restore", "system_upgrade"}
PHASE7_TOOLS = {"plan_app_upgrade", "execute_plan"}
PHASE8_TOOLS = {
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
}
PHASE10_TOOLS = {"audit_list", "audit_get"}
PHASE11_TOOLS = {"server_identity"}
PHASE13_TOOLS = {"approve_operation"}
PHASE14_TOOLS = {"diagnose_app", "validate_server", "safe_upgrade", "repair_app", "test_package"}

PHASE4_TOOLS = {
    "apps_list",
    "app_info",
    "app_resources",
    "diagnosis_run",
    "diagnosis_get",
    "services_list",
    "service_status",
    "domains_list",
    "users_list",
    "backups_list",
    "operations_list",
    "operation_status",
    "operation_logs",
    "updates_check",
}


@pytest.fixture(autouse=True)
def local_stdio_identity():
    set_current_request(LOCAL_STDIO_REQUEST)
    yield
    set_current_request(None)


SECOND_ADMIN_REQUEST = AuthenticatedRequest(
    pubkey="second-admin",
    event_id="a" * 64,
    event_created_at=0,
    identity=IdentityRecord(
        pubkey="second-admin", name="second admin", roles=("administrator",), scopes=scopes_for_roles(("administrator",))
    ),
)


async def _approve_as_second_admin(client: Client, confirmation_id: str) -> None:
    """Owner co-signing (Phase 13) requires a *different* identity than the
    requester - swap in a second administrator identity for one call, then
    restore LOCAL_STDIO_REQUEST so the rest of the test proceeds as before."""
    set_current_request(SECOND_ADMIN_REQUEST)
    try:
        result = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
        assert result.is_error is not True, result.content
    finally:
        set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_list_tools_exposes_all_v01_read_tools():
    async with Client(mcp) as client:
        result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        expected = (
            {"server_info", "health_check", "whoami"}
            | PHASE4_TOOLS
            | PHASE5_WRITE_TOOLS
            | PHASE6_WRITE_TOOLS
            | PHASE7_TOOLS
            | PHASE8_TOOLS
            | PHASE10_TOOLS
            | PHASE11_TOOLS
            | PHASE13_TOOLS
            | PHASE14_TOOLS
        )
        assert expected <= names


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("apps_list", {}),
        ("app_info", {"app": "nextcloud"}),
        ("app_resources", {"app": "nextcloud"}),
        ("diagnosis_run", {}),
        ("diagnosis_get", {}),
        ("services_list", {}),
        ("service_status", {"names": ["nginx"]}),
        ("domains_list", {}),
        ("users_list", {}),
        ("backups_list", {}),
        ("operations_list", {}),
        ("operation_status", {"name": "20260901-120000-app_install"}),
        ("operation_logs", {"name": "20260901-120000-app_install"}),
        ("updates_check", {}),
    ],
)
async def test_phase4_tool_succeeds_for_local_stdio_identity(tool: str, args: dict):
    async with Client(mcp) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error is not True, result.content
        assert result.structured_content is not None
        assert result.structured_content.get("fake") is True


@pytest.mark.anyio
async def test_phase4_tool_denied_for_identity_without_scope():
    # A "readonly" role has apps.read but not, say, backups.read revoked here
    # by using an identity with *no* roles at all: zero scopes, so every
    # scope-gated tool must be denied.
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("apps_list", {})
        assert result.is_error is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("service_restart", {"names": ["nginx"]}),
        ("backup_create", {"name": "test-backup"}),
        ("app_install", {"app": "nextcloud"}),
        ("app_upgrade", {"app": "nextcloud"}),
    ],
)
async def test_phase5_write_tool_succeeds_and_is_audited(tool: str, args: dict):
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error is not True, result.content
        assert result.structured_content is not None
        assert result.structured_content.get("fake") is True

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["caller"] == "local-stdio"
    assert entry["result"] == "success"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("backup_restore", {"name": "20260901-000000"}),
        ("system_upgrade", {}),
    ],
)
async def test_phase6_confirmable_write_requires_then_accepts_confirmation(tool: str, args: dict):
    async with Client(mcp) as client:
        first = await client.call_tool(tool, args)
        assert first.is_error is not True, first.content
        plan_response = first.structured_content
        assert plan_response["confirmation_required"] is True
        assert "operation_plan" in plan_response
        assert plan_response["owner_signature_required"] is True  # both tools default to Phase 13 co-signing
        confirmation_id = plan_response["confirmation_id"]

        # Calling again with the SAME args but no confirmation_id issues a
        # brand new ticket rather than executing - it never silently proceeds.
        second = await client.call_tool(tool, args)
        assert second.structured_content["confirmation_required"] is True
        assert second.structured_content["confirmation_id"] != confirmation_id

        # Not yet owner-approved: the original ticket must still refuse to execute.
        not_yet_approved = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert not_yet_approved.is_error is True

        await _approve_as_second_admin(client, confirmation_id)

        confirmed = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert confirmed.is_error is not True, confirmed.content
        assert confirmed.structured_content.get("fake") is True
        assert "confirmation_required" not in confirmed.structured_content


@pytest.mark.anyio
async def test_phase6_confirmation_rejected_for_mismatched_arguments():
    async with Client(mcp) as client:
        first = await client.call_tool("backup_restore", {"name": "archive-a"})
        confirmation_id = first.structured_content["confirmation_id"]

        # Same confirmation_id, different archive name - must not execute.
        mismatched = await client.call_tool(
            "backup_restore", {"name": "archive-b", "confirmation_id": confirmation_id}
        )
        assert mismatched.is_error is True


@pytest.mark.anyio
async def test_phase6_confirmation_is_one_shot():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]
        await _approve_as_second_admin(client, confirmation_id)

        ok = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert ok.is_error is not True

        reused = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert reused.is_error is True


@pytest.mark.anyio
async def test_phase13_execute_without_owner_approval_is_denied():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        result = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase13_self_approval_is_rejected():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        # LOCAL_STDIO_REQUEST trying to approve its own request.
        result = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase13_approve_operation_denied_for_non_administrator():
    package_developer = AuthenticatedRequest(
        pubkey="dev-pubkey",
        event_id="d" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="dev-pubkey",
            name="dev-agent",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
        ),
    )
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        set_current_request(package_developer)
        try:
            result = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
            assert result.is_error is True
        finally:
            set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_phase13_approve_operation_is_audited():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
        await _approve_as_second_admin(client, confirmation_id)
        new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]

    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "owner.approve"
    assert entry["caller"] == "second-admin"
    assert entry["result"] == "success"


@pytest.mark.anyio
async def test_phase13_approved_confirmation_can_still_be_used_for_a_second_call_attempt():
    # Approving doesn't consume the ticket - the agent may need more than
    # one attempt (e.g. a transient failure) before it actually executes,
    # as long as it's still the same confirmation_id/arguments.
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]
        await _approve_as_second_admin(client, confirmation_id)

        # Re-approving an already-approved ticket is fine (idempotent from
        # the store's perspective - it's still "different identity than
        # requester", just re-stamping the same approval).
        await _approve_as_second_admin(client, confirmation_id)

        result = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert result.is_error is not True


@pytest.mark.anyio
async def test_phase14_diagnose_app():
    async with Client(mcp) as client:
        result = await client.call_tool("diagnose_app", {"app": "nextcloud"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["app"] == "nextcloud"
        assert "app_info" in data
        assert "diagnosis" in data


@pytest.mark.anyio
async def test_phase14_validate_server():
    async with Client(mcp) as client:
        result = await client.call_tool("validate_server", {})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert "server" in data and "diagnosis" in data and "services" in data


@pytest.mark.anyio
async def test_phase14_safe_upgrade_runs_full_workflow_and_is_audited():
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        result = await client.call_tool("safe_upgrade", {"app": "nextcloud"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["passed"] is True
        assert [s["step"] for s in data["steps"]][:4] == ["pre_diagnosis", "inspect_app", "backup", "upgrade"]

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "apps.upgrade"
    assert entry["result"] == "success"


@pytest.mark.anyio
async def test_phase14_safe_upgrade_blocked_by_free_space_policy(monkeypatch: pytest.MonkeyPatch):
    from yunohost_mcp import server as server_module

    def huge_minimum(*args, **kwargs):
        raise server_module.PolicyViolation("not enough free space")

    monkeypatch.setattr(server_module, "check_free_space", huge_minimum)
    async with Client(mcp) as client:
        result = await client.call_tool("safe_upgrade", {"app": "nextcloud"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase14_repair_app():
    async with Client(mcp) as client:
        result = await client.call_tool("repair_app", {"app": "nextcloud"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["strategy"] == "conservative"
        assert "diagnosis_before" in data and "diagnosis_after" in data


@pytest.mark.anyio
async def test_phase14_repair_app_rejects_unknown_strategy():
    async with Client(mcp) as client:
        result = await client.call_tool("repair_app", {"app": "nextcloud", "strategy": "aggressive"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase14_test_package_matches_package_run_tests():
    async with Client(mcp) as client:
        result = await client.call_tool("test_package", {"source": "/tmp/example_ynh"})
        assert result.is_error is not True, result.content
        assert result.structured_content["passed"] is True


@pytest.mark.anyio
async def test_phase14_composite_tools_denied_for_identity_without_scope():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        for tool, args in [
            ("diagnose_app", {"app": "nextcloud"}),
            ("validate_server", {}),
            ("safe_upgrade", {"app": "nextcloud"}),
            ("repair_app", {"app": "nextcloud"}),
            ("test_package", {"source": "/tmp/example_ynh"}),
        ]:
            result = await client.call_tool(tool, args)
            assert result.is_error is True, f"{tool} should have been denied"


@pytest.mark.anyio
async def test_phase6_app_remove_blocked_by_stale_backup_policy():
    # Fake backups_list() returns a single, deliberately old archive
    # ("20260901-000000") - older than apps.remove's default 24h max age -
    # so app_remove should be blocked by the hard policy check before it
    # ever gets to the confirmation step.
    async with Client(mcp) as client:
        result = await client.call_tool("app_remove", {"app": "nextcloud"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase7_plan_then_execute_upgrades_the_app():
    async with Client(mcp) as client:
        plan = await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
        assert plan.is_error is not True, plan.content
        data = plan.structured_content
        assert data["app"] == "nextcloud"
        assert data["upgradable"] is True
        assert data["blocked"] is False
        plan_id = data["plan_id"]

        executed = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert executed.is_error is not True, executed.content
        assert executed.structured_content["app"] == "nextcloud"


@pytest.mark.anyio
async def test_phase7_plan_app_upgrade_does_not_write_audit_entry():
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
    new_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    assert new_lines == existing_lines


@pytest.mark.anyio
async def test_phase7_execute_plan_rejects_unknown_plan_id():
    async with Client(mcp) as client:
        result = await client.call_tool("execute_plan", {"plan_id": "plan-does-not-exist"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase7_execute_plan_is_one_shot():
    async with Client(mcp) as client:
        plan = await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
        plan_id = plan.structured_content["plan_id"]

        first = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert first.is_error is not True

        second = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert second.is_error is True


@pytest.mark.anyio
async def test_phase6_write_tool_denied_for_identity_without_scope():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("system_upgrade", {})
        assert result.is_error is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("package_inspect", {"source": "/tmp/example_ynh"}),
        ("package_lint", {"source": "/tmp/example_ynh"}),
        ("package_install_test", {"source": "/tmp/example_ynh"}),
        ("package_upgrade_test", {"app": "example", "source": "/tmp/example_ynh"}),
        ("package_backup_test", {"app": "example"}),
        ("package_restore_test", {"app": "example", "archive_name": "package-test-example"}),
        ("package_change_url_test", {"app": "example", "domain": "new.example.com", "path": "/"}),
        ("package_remove_test", {"app": "example"}),
        ("package_logs", {"operation": "20260901-120000-app_install"}),
        ("package_run_tests", {"source": "/tmp/example_ynh"}),
    ],
)
async def test_phase8_package_tool_succeeds_for_local_stdio_identity(tool: str, args: dict):
    async with Client(mcp) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error is not True, result.content
        assert result.structured_content is not None
        assert result.structured_content.get("fake") is True


@pytest.mark.anyio
async def test_phase8_package_run_tests_writes_one_audit_entry_for_the_whole_cycle():
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        result = await client.call_tool("package_run_tests", {"source": "/tmp/example_ynh"})
        assert result.is_error is not True
        assert result.structured_content["passed"] is True

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "packages.test"
    assert entry["result"] == "success"


@pytest.mark.anyio
async def test_phase8_package_test_tool_denied_for_identity_without_scope():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("package_install_test", {"source": "/tmp/example_ynh"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase8_package_developer_role_can_test_but_not_administer():
    developer = AuthenticatedRequest(
        pubkey="feedface",
        event_id="f" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="feedface", name="dev-agent", roles=("package-developer",), scopes=scopes_for_roles(("package-developer",))
        ),
    )
    set_current_request(developer)
    async with Client(mcp) as client:
        install = await client.call_tool("package_install_test", {"source": "/tmp/example_ynh"})
        assert install.is_error is not True, install.content

        # package-developer does not grant system.upgrade.
        denied = await client.call_tool("system_upgrade", {})
        assert denied.is_error is True


@pytest.mark.anyio
async def test_server_info_returns_fake_version_data():
    async with Client(mcp) as client:
        result = await client.call_tool("server_info", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data is not None
        assert data["fake"] is True
        assert "yunohost" in data


@pytest.mark.anyio
async def test_health_check_returns_fake_diagnosis_categories():
    async with Client(mcp) as client:
        result = await client.call_tool("health_check", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data is not None
        assert data["fake"] is True
        assert len(data["categories"]) > 0


@pytest.mark.anyio
async def test_whoami_reports_local_stdio_identity():
    async with Client(mcp) as client:
        result = await client.call_tool("whoami", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data is not None
        assert data["authenticated"] is True
        assert data["pubkey"] == "local-stdio"
        assert "administrator" in data["roles"]


@pytest.mark.anyio
async def test_server_identity_tool_returns_npub_and_pubkey():
    async with Client(mcp) as client:
        result = await client.call_tool("server_identity", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data["npub"].startswith("npub1")
        assert len(data["pubkey"]) == 64

        # Calling it again returns the *same* identity (lazy singleton,
        # not regenerated per call).
        again = await client.call_tool("server_identity", {})
        assert again.structured_content == data


@pytest.mark.anyio
async def test_phase9_tool_response_is_redacted_end_to_end(monkeypatch: pytest.MonkeyPatch):
    """A secret-shaped field anywhere in a tool's real return value must
    never reach the MCP client - proves @redact_response actually runs on
    the full protocol path (structured_content), not just as a unit test
    of the decorator in isolation."""
    from yunohost_mcp import server as server_module

    def leaky_server_info():
        return {
            "fake": True,
            "yunohost": {"version": "12.0.0"},
            "db_password": "s3cr3t-should-not-leak",
            "settings": {"ldap_password": "also-secret", "domain": "example.com"},
        }

    monkeypatch.setattr(server_module.adapter, "server_info", leaky_server_info)

    async with Client(mcp) as client:
        result = await client.call_tool("server_info", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data["db_password"] == "[REDACTED]"
        assert data["settings"]["ldap_password"] == "[REDACTED]"
        assert data["settings"]["domain"] == "example.com"
        assert data["yunohost"]["version"] == "12.0.0"

        # Also check the text content mirror the framework generates - a
        # naive fix that only redacted structured_content and not the text
        # representation would still leak the secret there.
        text_blob = " ".join(getattr(c, "text", "") for c in result.content)
        assert "s3cr3t-should-not-leak" not in text_blob
        assert "also-secret" not in text_blob


@pytest.mark.anyio
async def test_phase10_audit_list_and_get_administrator_only():
    async with Client(mcp) as client:
        install = await client.call_tool("app_install", {"app": "nextcloud"})
        assert install.is_error is not True

        listed = await client.call_tool("audit_list", {"limit": 1})
        assert listed.is_error is not True
        entries = listed.structured_content["entries"]
        assert len(entries) == 1
        assert entries[0]["tool"] == "apps.install"
        audit_id = entries[0]["audit_id"]

        got = await client.call_tool("audit_get", {"audit_id": audit_id})
        assert got.is_error is not True
        assert got.structured_content["audit_id"] == audit_id
        assert got.structured_content["tool"] == "apps.install"


@pytest.mark.anyio
async def test_phase10_audit_get_unknown_id_errors():
    async with Client(mcp) as client:
        result = await client.call_tool("audit_get", {"audit_id": "mcp-does-not-exist"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase10_audit_tools_denied_for_non_administrator_roles():
    developer = AuthenticatedRequest(
        pubkey="feedface",
        event_id="f" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="feedface",
            name="dev-agent",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
        ),
    )
    set_current_request(developer)
    async with Client(mcp) as client:
        result = await client.call_tool("audit_list", {})
        assert result.is_error is True


@pytest.fixture
def anyio_backend():
    return "asyncio"
