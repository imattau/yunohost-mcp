"""Tests for delegate.py: signing a delegation event client-side, and (the
integration test) actually using it end-to-end against a real live server -
the same delegation event a genuine agent identity would present via
`yunohost-mcp-connect --delegation-file` must be accepted, and the scopes
it received must be exactly the intersection this project's delegation
model promises (auth/delegation.py's docstring).
"""

from __future__ import annotations

import argparse
import asyncio
import json

import httpx2
import pytest
import uvicorn
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from yunohost_mcp import server as server_module
from yunohost_mcp.auth.delegation import DEFAULT_MAX_LIFETIME_SECONDS
from yunohost_mcp.auth.signing import ClientIdentity
from yunohost_mcp.bridge import BridgeConfigError, Nip98BridgeAuth, _build_local_server
from yunohost_mcp.delegate import (
    _async_main,
    _fetch_server_context,
    _parse_duration,
    _resolve_pubkey,
    _resolve_scopes,
    _sign_delegation,
)


def _args(**overrides) -> argparse.Namespace:
    base = dict(
        key=None,
        key_file=None,
        delegate=None,
        server=None,
        remote_url=None,
        scope=None,
        role=None,
        ttl="24h",
        out=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_parse_duration_units():
    assert _parse_duration("30m") == 30 * 60
    assert _parse_duration("24h") == 24 * 3600
    assert _parse_duration("7d") == 7 * 86400
    assert _parse_duration("90") == 90 * 3600  # bare number defaults to hours


def test_parse_duration_rejects_garbage():
    with pytest.raises(BridgeConfigError):
        _parse_duration("banana")
    with pytest.raises(BridgeConfigError):
        _parse_duration("5x")


def test_resolve_pubkey_accepts_hex_and_npub():
    identity = ClientIdentity.from_key_string("a" * 64)
    assert _resolve_pubkey(identity.pubkey_hex, what="--x") == identity.pubkey_hex
    assert _resolve_pubkey(identity.npub, what="--x") == identity.pubkey_hex


def test_resolve_pubkey_rejects_nsec():
    with pytest.raises(BridgeConfigError, match="private key"):
        _resolve_pubkey("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5", what="--x")


def test_resolve_scopes_from_role_and_explicit_scope():
    args = _args(role=["readonly"], scope=["backups.create"])
    scopes = _resolve_scopes(args)
    assert "server.read" in scopes
    assert "backups.create" in scopes


def test_resolve_scopes_rejects_unknown_role_and_scope():
    with pytest.raises(BridgeConfigError, match="unknown role"):
        _resolve_scopes(_args(role=["superuser"]))
    with pytest.raises(BridgeConfigError, match="unknown scope"):
        _resolve_scopes(_args(scope=["not.a.real.scope"]))


def test_resolve_scopes_requires_at_least_one():
    with pytest.raises(BridgeConfigError, match="nothing to delegate"):
        _resolve_scopes(_args())


def test_sign_delegation_rejects_ttl_over_server_maximum():
    identity = ClientIdentity.from_key_string("a" * 64)
    with pytest.raises(BridgeConfigError, match="maximum"):
        _sign_delegation(
            identity,
            delegate_pubkey="b" * 64,
            server_pubkey="c" * 64,
            scopes=["server.read"],
            ttl_seconds=DEFAULT_MAX_LIFETIME_SECONDS + 3600,
        )


def test_sign_delegation_produces_a_verifiable_event():
    owner = ClientIdentity.from_key_string("a" * 64)
    delegate_pubkey = ClientIdentity.from_key_string("b" * 64).pubkey_hex
    server_pubkey = ClientIdentity.from_key_string("c" * 64).pubkey_hex

    event = _sign_delegation(
        owner,
        delegate_pubkey=delegate_pubkey,
        server_pubkey=server_pubkey,
        scopes=["server.read", "apps.read"],
        ttl_seconds=3600,
    )

    assert event.pubkey == owner.pubkey_hex
    assert event.tag("p") == delegate_pubkey
    assert event.tag("server") == server_pubkey
    assert sorted(t[1] for t in event.tags if t[0] == "scope") == ["apps.read", "server.read"]

    from yunohost_mcp.auth.nostr import verify_event

    verify_event(event)  # raises on a bad signature/id - must not raise here


class _LiveServer:
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
def owner_identity():
    identity = ClientIdentity.from_key_string("d" * 64)
    _seed_identity(identity.npub, name="delegating owner", roles=["app-admin"])
    yield identity
    server_module.settings.identity_file_path().unlink(missing_ok=True)


@pytest.mark.anyio
async def test_fetch_server_context_returns_pubkey_and_own_scopes(owner_identity):
    async with _LiveServer() as live:
        server_pubkey, own_scopes = await _fetch_server_context(live.url, owner_identity)
        assert server_pubkey == server_module.get_server_identity().pubkey_hex
        assert "apps.install" in own_scopes  # app-admin's own role grants this


@pytest.mark.anyio
async def test_full_delegation_end_to_end(owner_identity, capsys):
    """The end-to-end promise this tool exists for: sign a delegation with
    --remote-url auto-discovery, then have a *different* identity (the
    delegate, never added to identity.toml itself) actually use it to call
    a tool through the real middleware."""
    agent = ClientIdentity.from_key_string("e" * 64)

    async with _LiveServer() as live:
        args = _args(
            key=owner_identity.private_key.secret.hex(),
            delegate=agent.pubkey_hex,
            remote_url=live.url,
            role=["readonly"],
            ttl="1h",
        )
        await _async_main(args)
        printed = capsys.readouterr().out
        event = json.loads(printed)

        import base64

        delegation_header = base64.b64encode(json.dumps(event).encode()).decode()

        auth = Nip98BridgeAuth(agent, delegation_header)
        async with httpx2.AsyncClient(auth=auth) as http_client:
            transport = streamable_http_client(live.url, http_client=http_client)
            async with Client(transport) as remote:
                local = _build_local_server(remote, name="test-delegate")
                async with Client(local) as local_client:
                    who = await local_client.call_tool("whoami", {})
                    assert who.is_error is not True
                    assert who.structured_content["authenticated"] is True
                    assert who.structured_content["pubkey"] == agent.pubkey_hex
                    assert "server.read" in who.structured_content["scopes"]
                    assert "apps.install" not in who.structured_content["scopes"]

                    denied = await local_client.call_tool("app_install", {"app": "nextcloud"})
                    assert denied.is_error is True


@pytest.mark.anyio
async def test_excess_scope_request_warns_but_still_signs(owner_identity, capsys):
    agent = ClientIdentity.from_key_string("1" + "2" * 63)
    async with _LiveServer() as live:
        args = _args(
            key=owner_identity.private_key.secret.hex(),
            delegate=agent.pubkey_hex,
            remote_url=live.url,
            role=["administrator"],  # owner only has app-admin, not administrator
            ttl="1h",
        )
        await _async_main(args)
        stderr = capsys.readouterr().err
        assert "warning" in stderr
        assert "silently drop" in stderr


@pytest.fixture
def anyio_backend():
    return "asyncio"
