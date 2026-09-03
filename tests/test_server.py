"""End-to-end smoke test: a real MCP client session against yunohost_mcp.server.

Uses the MCP SDK's in-process `Client` (backed by `InMemoryTransport`) so this
exercises the actual MCP protocol (tool listing, tool call, JSON-RPC framing)
rather than just calling the underlying Python functions directly.

This exercises the stdio-equivalent path, which is implicitly fully
trusted (see auth/identity.py's LOCAL_STDIO_REQUEST) — so tests set that
context themselves, the way server.py's stdio branch of main() does.
"""

from __future__ import annotations

import pytest
from mcp.client import Client

from yunohost_mcp.auth.identity import AuthenticatedRequest, IdentityRecord, LOCAL_STDIO_REQUEST, set_current_request
from yunohost_mcp.policy.roles import scopes_for_roles
from yunohost_mcp.server import mcp

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
        assert {"server_info", "health_check", "whoami"} | PHASE4_TOOLS <= names


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
