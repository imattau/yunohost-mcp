"""End-to-end smoke test: a real MCP client session against yunohost_mcp.server.

Uses the MCP SDK's in-process `Client` (backed by `InMemoryTransport`) so this
exercises the actual MCP protocol (tool listing, tool call, JSON-RPC framing)
rather than just calling the underlying Python functions directly.
"""

from __future__ import annotations

import pytest
from mcp.client import Client

from yunohost_mcp.server import mcp


@pytest.mark.anyio
async def test_list_tools_exposes_phase1_tools():
    async with Client(mcp) as client:
        result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        assert {"server_info", "health_check"} <= names


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


@pytest.fixture
def anyio_backend():
    return "asyncio"
