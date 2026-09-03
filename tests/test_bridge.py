"""End-to-end integration test for bridge.py: a real local MCPServer
(built the same way _build_local_server does) driven by a real MCP
Client, forwarding to a real, live yunohost_mcp.server HTTP server over a
real NIP-98-signed request - actual TCP sockets on an OS-assigned
ephemeral port (127.0.0.1:0), run as a background task for the duration
of each test, not the in-process ASGITransport shortcut every other
integration test in this suite uses: the session manager mcp's own
streamable-http app relies on needs a real ASGI lifespan startup, which
only a real server (uvicorn here) drives correctly.
"""

from __future__ import annotations

import asyncio

import httpx2
import pytest
import uvicorn
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from yunohost_mcp import server as server_module
from yunohost_mcp.auth.signing import ClientIdentity
from yunohost_mcp.bridge import Nip98BridgeAuth, _build_local_server


class _LiveServer:
    """Runs yunohost_mcp.server's real HTTP app on 127.0.0.1:<ephemeral>
    for the lifetime of an `async with` block."""

    def __init__(self) -> None:
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None
        self.url: str = ""

    async def __aenter__(self) -> "_LiveServer":
        app = server_module.create_http_app()
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
        self._server = uvicorn.Server(config)
        self._task = asyncio.create_task(self._server.serve())
        while not self._server.started:
            await asyncio.sleep(0.01)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"
        return self

    async def __aexit__(self, *exc_info) -> None:
        assert self._server is not None
        self._server.should_exit = True
        await self._task


def _seed_identity(npub: str, *, name: str, roles: list[str]) -> None:
    identity_path = server_module.settings.identity_file_path()
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    roles_toml = ", ".join(f'"{r}"' for r in roles)
    identity_path.write_text(f'[identity."{npub}"]\nname = "{name}"\nroles = [{roles_toml}]\n')


@pytest.fixture
def bridge_identity():
    identity = ClientIdentity.from_key_string("b" * 64)
    _seed_identity(identity.npub, name="bridge test identity", roles=["administrator"])
    yield identity
    server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.mark.anyio
async def test_bridge_forwards_tools_list_and_call_over_real_signed_http(bridge_identity):
    async with _LiveServer() as live:
        auth = Nip98BridgeAuth(bridge_identity)
        async with httpx2.AsyncClient(auth=auth) as http_client:
            transport = streamable_http_client(live.url, http_client=http_client)
            async with Client(transport) as remote:
                local = _build_local_server(remote, name="test-bridge")

                async with Client(local) as local_client:
                    tools = await local_client.list_tools()
                    names = {t.name for t in tools.tools}
                    assert "whoami" in names
                    assert "apps_list" in names

                    result = await local_client.call_tool("whoami", {})
                    assert result.is_error is not True
                    assert result.structured_content["pubkey"] == bridge_identity.pubkey_hex
                    assert result.structured_content["authenticated"] is True

                    apps = await local_client.call_tool("apps_list", {})
                    assert apps.is_error is not True
                    assert apps.structured_content["fake"] is True


@pytest.mark.anyio
async def test_bridge_forwards_resource_reads(bridge_identity):
    async with _LiveServer() as live:
        auth = Nip98BridgeAuth(bridge_identity)
        async with httpx2.AsyncClient(auth=auth) as http_client:
            transport = streamable_http_client(live.url, http_client=http_client)
            async with Client(transport) as remote:
                local = _build_local_server(remote, name="test-bridge")

                async with Client(local) as local_client:
                    resources = await local_client.list_resources()
                    uris = {str(r.uri) for r in resources.resources}
                    assert "yunohost://server" in uris

                    read = await local_client.read_resource("yunohost://server")
                    assert read.contents


@pytest.mark.anyio
async def test_bridge_denies_a_request_the_remote_identity_lacks_scope_for():
    identity = ClientIdentity.from_key_string("c" * 64)
    _seed_identity(identity.npub, name="readonly", roles=["readonly"])
    try:
        async with _LiveServer() as live:
            auth = Nip98BridgeAuth(identity)
            async with httpx2.AsyncClient(auth=auth) as http_client:
                transport = streamable_http_client(live.url, http_client=http_client)
                async with Client(transport) as remote:
                    local = _build_local_server(remote, name="test-bridge")
                    async with Client(local) as local_client:
                        result = await local_client.call_tool("app_install", {"app": "nextcloud"})
                        assert result.is_error is True
    finally:
        server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.fixture
def anyio_backend():
    return "asyncio"
