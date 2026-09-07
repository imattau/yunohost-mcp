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

import anyio
import httpx2
import pytest
import uvicorn
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from yunohost_mcp import server as server_module
from yunohost_mcp.auth.signing import ClientIdentity
from yunohost_mcp import bridge as bridge_module
from yunohost_mcp.bridge import (
    Nip98BridgeAuth,
    RemoteSession,
    _build_local_server,
    _build_multi_host_local_server,
)


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
async def test_remote_session_forwards_tools_list_over_real_http(bridge_identity):
    """RemoteSession, not just a pre-connected Client, must be able to drive a
    real streamable_http_client transport end to end. RemoteSession._connect
    passes the transport it builds into `Client(...)` without entering it
    itself first - Client enters it internally - and only a real (non-mocked)
    streamable_http_client/Client pair exercises that contract."""
    async with _LiveServer() as live:
        auth = Nip98BridgeAuth(bridge_identity)
        async with httpx2.AsyncClient(auth=auth) as http_client:
            async with anyio.create_task_group() as task_group:
                remote = RemoteSession(live.url, http_client, task_group)
                local = _build_local_server(remote, name="test-bridge")
                try:
                    async with Client(local) as local_client:
                        tools = await local_client.list_tools()
                        names = {t.name for t in tools.tools}
                        assert "whoami" in names
                        assert "apps_list" in names
                finally:
                    await remote.close()


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


@pytest.mark.anyio
async def test_bridge_completes_local_handshake_when_remote_is_down(monkeypatch):
    """One unavailable YunoHost must not block other MCP servers at startup."""

    def fail_to_create_transport(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(bridge_module, "streamable_http_client", fail_to_create_transport)
    async with anyio.create_task_group() as task_group:
        remote = RemoteSession("https://offline.example/mcp", http_client=None, task_group=task_group)  # type: ignore[arg-type]
        local = _build_local_server(remote, name="offline-bridge")

        async with Client(local) as local_client:
            tools = await local_client.list_tools()
            assert tools.tools == []

            result = await local_client.call_tool("whoami", {})
            assert result.is_error is True
            assert "offline.example" in result.content[0].text

        await remote.close()


@pytest.mark.anyio
async def test_remote_session_keeps_forwarding_after_successful_connection(monkeypatch):
    class FakeTransport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

    class FakeRemote:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def list_tools(self, *, cursor=None):
            return "forwarded"

    monkeypatch.setattr(bridge_module, "streamable_http_client", lambda *args, **kwargs: FakeTransport())
    monkeypatch.setattr(bridge_module, "Client", lambda transport: FakeRemote())
    async with anyio.create_task_group() as task_group:
        remote = RemoteSession("https://online.example/mcp", http_client=None, task_group=task_group)  # type: ignore[arg-type]

        assert await remote.request(lambda connected: connected.list_tools()) == "forwarded"
        assert await remote.request(lambda connected: connected.list_tools()) == "forwarded"

        await remote.close()


@pytest.mark.anyio
async def test_remote_session_retries_after_a_failed_connection(monkeypatch):
    attempts = 0

    class FakeTransport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

    class FakeRemote:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def list_tools(self, *, cursor=None):
            return "recovered"

    def eventually_connect(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("connection refused")
        return FakeTransport()

    monkeypatch.setattr(bridge_module, "streamable_http_client", eventually_connect)
    monkeypatch.setattr(bridge_module, "Client", lambda transport: FakeRemote())
    async with anyio.create_task_group() as task_group:
        remote = RemoteSession("https://recovering.example/mcp", http_client=None, task_group=task_group)  # type: ignore[arg-type]
        remote.RETRY_DELAY_SECONDS = 0

        with pytest.raises(bridge_module.RemoteUnavailable):
            await remote.request(lambda connected: connected.list_tools())
        assert await remote.request(lambda connected: connected.list_tools()) == "recovered"
        assert attempts == 2

        await remote.close()


def _seed_identities(entries: list[tuple[str, str, list[str]]]) -> None:
    """Like _seed_identity, but writes several identities into one file at
    once - both `_LiveServer` instances in a multi-host test share the same
    global `server_module.settings` identity store, so each host's identity
    must coexist in it rather than overwrite the other's."""
    identity_path = server_module.settings.identity_file_path()
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    blocks = []
    for npub, name, roles in entries:
        roles_toml = ", ".join(f'"{r}"' for r in roles)
        blocks.append(f'[identity."{npub}"]\nname = "{name}"\nroles = [{roles_toml}]\n')
    identity_path.write_text("\n".join(blocks))


@pytest.mark.anyio
async def test_multi_host_bridge_merges_tools_and_routes_calls_by_host():
    identity_a = ClientIdentity.from_key_string("a" * 64)
    identity_b = ClientIdentity.from_key_string("d" * 64)
    _seed_identities(
        [
            (identity_a.npub, "host a", ["administrator"]),
            (identity_b.npub, "host b", ["administrator"]),
        ]
    )
    try:
        async with _LiveServer() as live_a, _LiveServer() as live_b:
            async with anyio.create_task_group() as task_group:
                async with httpx2.AsyncClient(auth=Nip98BridgeAuth(identity_a)) as http_a, httpx2.AsyncClient(
                    auth=Nip98BridgeAuth(identity_b)
                ) as http_b:
                    session_a = RemoteSession(live_a.url, http_a, task_group)
                    session_b = RemoteSession(live_b.url, http_b, task_group)
                    local = _build_multi_host_local_server({"a": session_a, "b": session_b}, name="multi-test")

                    async with Client(local) as local_client:
                        tools = await local_client.list_tools()
                        by_name = {t.name: t for t in tools.tools}
                        assert [t.name for t in tools.tools].count("whoami") == 1

                        schema = by_name["whoami"].input_schema
                        assert schema["properties"]["host"]["enum"] == ["a", "b"]
                        assert "host" in schema["required"]

                        result_a = await local_client.call_tool("whoami", {"host": "a"})
                        assert result_a.is_error is not True
                        assert result_a.structured_content["pubkey"] == identity_a.pubkey_hex

                        result_b = await local_client.call_tool("whoami", {"host": "b"})
                        assert result_b.is_error is not True
                        assert result_b.structured_content["pubkey"] == identity_b.pubkey_hex

                        missing_host = await local_client.call_tool("whoami", {})
                        assert missing_host.is_error is True

                        bad_host = await local_client.call_tool("whoami", {"host": "c"})
                        assert bad_host.is_error is True

                    await session_a.close()
                    await session_b.close()
    finally:
        server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.mark.anyio
async def test_multi_host_bridge_prefixes_resource_uris_by_host_and_round_trips_reads():
    identity_a = ClientIdentity.from_key_string("a" * 64)
    identity_b = ClientIdentity.from_key_string("d" * 64)
    _seed_identities(
        [
            (identity_a.npub, "host a", ["administrator"]),
            (identity_b.npub, "host b", ["administrator"]),
        ]
    )
    try:
        async with _LiveServer() as live_a, _LiveServer() as live_b:
            async with anyio.create_task_group() as task_group:
                async with httpx2.AsyncClient(auth=Nip98BridgeAuth(identity_a)) as http_a, httpx2.AsyncClient(
                    auth=Nip98BridgeAuth(identity_b)
                ) as http_b:
                    session_a = RemoteSession(live_a.url, http_a, task_group)
                    session_b = RemoteSession(live_b.url, http_b, task_group)
                    local = _build_multi_host_local_server({"a": session_a, "b": session_b}, name="multi-test")

                    async with Client(local) as local_client:
                        resources = await local_client.list_resources()
                        uris = {str(r.uri) for r in resources.resources}
                        assert "yunohost://a.server" in uris
                        assert "yunohost://b.server" in uris

                        read = await local_client.read_resource("yunohost://a.server")
                        assert read.contents

                    await session_a.close()
                    await session_b.close()
    finally:
        server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.mark.anyio
async def test_multi_host_bridge_still_lists_other_hosts_tools_when_one_is_down(monkeypatch):
    identity_a = ClientIdentity.from_key_string("a" * 64)
    _seed_identity(identity_a.npub, name="host a", roles=["administrator"])

    real_streamable_http_client = bridge_module.streamable_http_client

    def flaky_streamable_http_client(url, *args, **kwargs):
        if url == "https://offline.example/mcp":
            raise OSError("connection refused")
        return real_streamable_http_client(url, *args, **kwargs)

    monkeypatch.setattr(bridge_module, "streamable_http_client", flaky_streamable_http_client)

    try:
        async with _LiveServer() as live_a:
            async with anyio.create_task_group() as task_group:
                async with httpx2.AsyncClient(auth=Nip98BridgeAuth(identity_a)) as http_a:
                    session_a = RemoteSession(live_a.url, http_a, task_group)
                    session_down = RemoteSession("https://offline.example/mcp", http_a, task_group)
                    local = _build_multi_host_local_server(
                        {"a": session_a, "down": session_down}, name="multi-test"
                    )

                    async with Client(local) as local_client:
                        tools = await local_client.list_tools()
                        names = {t.name for t in tools.tools}
                        assert "whoami" in names

                        # "down"'s tools never made it into the merged list, so it's
                        # simply not a valid `host` value for any tool - not a crash.
                        result = await local_client.call_tool("whoami", {"host": "down"})
                        assert result.is_error is True

                    await session_a.close()
                    await session_down.close()
    finally:
        server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.mark.anyio
async def test_multi_host_bridge_notifies_client_when_a_host_recovers(monkeypatch):
    identity_a = ClientIdentity.from_key_string("a" * 64)
    identity_b = ClientIdentity.from_key_string("d" * 64)
    _seed_identities(
        [
            (identity_a.npub, "host a", ["administrator"]),
            (identity_b.npub, "host b", ["administrator"]),
        ]
    )

    monkeypatch.setattr(bridge_module, "TOOL_POLL_INTERVAL_SECONDS", 0.05)

    notified: list[bool] = []

    async def fake_send_tool_list_changed(self) -> None:
        notified.append(True)

    monkeypatch.setattr("mcp.server.session.ServerSession.send_tool_list_changed", fake_send_tool_list_changed)

    try:
        async with _LiveServer() as live_a, _LiveServer() as live_b:
            host_b_reachable = [False]
            real_streamable_http_client = bridge_module.streamable_http_client

            def flaky_streamable_http_client(url, *args, **kwargs):
                if url == live_b.url and not host_b_reachable[0]:
                    raise OSError("connection refused")
                return real_streamable_http_client(url, *args, **kwargs)

            monkeypatch.setattr(bridge_module, "streamable_http_client", flaky_streamable_http_client)

            async with anyio.create_task_group() as task_group:
                async with httpx2.AsyncClient(auth=Nip98BridgeAuth(identity_a)) as http_a, httpx2.AsyncClient(
                    auth=Nip98BridgeAuth(identity_b)
                ) as http_b:
                    session_a = RemoteSession(live_a.url, http_a, task_group)
                    session_b = RemoteSession(live_b.url, http_b, task_group)
                    session_b.RETRY_DELAY_SECONDS = 0
                    local = _build_multi_host_local_server({"a": session_a, "b": session_b}, name="multi-test")
                    task_group.start_soon(local._poll_for_host_changes)  # noqa: SLF001 - exercising the stashed poller

                    async with Client(local) as local_client:
                        baseline = await local_client.list_tools()
                        by_name = {t.name: t for t in baseline.tools}
                        assert by_name["whoami"].input_schema["properties"]["host"]["enum"] == ["a"]

                        host_b_reachable[0] = True
                        with anyio.fail_after(5):
                            while not notified:
                                await anyio.sleep(0.05)

                        recovered = await local_client.list_tools()
                        by_name = {t.name: t for t in recovered.tools}
                        assert by_name["whoami"].input_schema["properties"]["host"]["enum"] == ["a", "b"]

                    await session_a.close()
                    await session_b.close()
                task_group.cancel_scope.cancel()
    finally:
        server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.fixture
def anyio_backend():
    return "asyncio"
