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

PHASE4_TOOLS = {
    "apps_list",
    "app_info",
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


@pytest.mark.anyio
async def test_list_tools_exposes_all_v01_read_tools():
    async with Client(mcp) as client:
        result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        assert {"server_info", "health_check", "whoami"} | PHASE4_TOOLS | PHASE5_WRITE_TOOLS <= names


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("apps_list", {}),
        ("app_info", {"app": "nextcloud"}),
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
        confirmation_id = plan_response["confirmation_id"]

        # Calling again with the SAME args but no confirmation_id issues a
        # brand new ticket rather than executing - it never silently proceeds.
        second = await client.call_tool(tool, args)
        assert second.structured_content["confirmation_required"] is True
        assert second.structured_content["confirmation_id"] != confirmation_id

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

        ok = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert ok.is_error is not True

        reused = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert reused.is_error is True


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


@pytest.fixture
def anyio_backend():
    return "asyncio"
