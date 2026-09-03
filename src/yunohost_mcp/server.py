"""yunohost-mcp server.

Phase 1: minimal MCP foundation, stdio transport.
Phase 2: adds a Streamable HTTP transport wrapped in NIP-98 authentication
(auth/middleware.py) — proves *who* is calling.
Phase 3: adds identity.toml authorization on top — proves *what* they may
do. A validly-signed request from a pubkey with no identity.toml entry (or
an expired one) is rejected before it ever reaches a tool; a request from a
known identity can only call tools whose required scope its roles grant.
`server_info` and `health_check` remain the only real tools; the rest of
PLAN.md's v0.1 scope follows in later phases.
"""

from __future__ import annotations

import argparse
from typing import Any

from mcp.server.mcpserver import MCPServer

from yunohost_mcp.auth.identity import LOCAL_STDIO_REQUEST, IdentityStore, get_current_request, set_current_request
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.config import load_settings
from yunohost_mcp.policy.enforcement import require_scope
from yunohost_mcp.policy.scopes import Scope
from yunohost_mcp.yunohost.adapter import YunohostAdapter

settings = load_settings()
adapter = YunohostAdapter(settings=settings)

mcp = MCPServer(settings.server_name)


@mcp.tool()
@require_scope(Scope.SERVER_READ)
def server_info() -> dict[str, Any]:
    """Return YunoHost server/component version information."""
    return adapter.server_info()


@mcp.tool()
@require_scope(Scope.DIAGNOSIS_READ)
def health_check() -> dict[str, Any]:
    """Return a summary YunoHost diagnosis report."""
    return adapter.health_check()


@mcp.tool()
def whoami() -> dict[str, Any]:
    """Return the caller's resolved Nostr identity: pubkey, name, roles, and scopes.

    Requires no scope of its own — any authenticated, identity.toml-mapped
    caller may ask who they are, even one whose roles grant nothing else.
    Only meaningful over the HTTP transport; over stdio there is no NIP-98
    handshake, so this returns unauthenticated.
    """
    request = get_current_request()
    if request is None or request.identity is None:
        return {"authenticated": False, "pubkey": None}
    return {
        "authenticated": True,
        "pubkey": request.pubkey,
        "name": request.identity.name,
        "roles": list(request.identity.roles),
        "scopes": sorted(s.value for s in request.scopes),
    }


def create_http_app():
    """Build the ASGI app for the Streamable HTTP transport: MCP wrapped in NIP-98 auth + authz."""
    inner_app = mcp.streamable_http_app()
    identity_store = IdentityStore.load(settings.identity_file_path())
    return NostrAuthMiddleware(
        inner_app,
        identity_store=identity_store,
        replay_cache=ReplayCache(ttl_seconds=settings.nip98_replay_ttl_seconds),
        clock_skew_seconds=settings.nip98_clock_skew_seconds,
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog=settings.server_name)
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="stdio for local MCP clients, http for NIP-98-authenticated remote access",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if args.transport == "stdio":
        # No NIP-98 handshake applies to stdio: whoever can run this process
        # locally already has the access level a `yunohost` CLI invocation
        # would. See auth/identity.py's LOCAL_STDIO_REQUEST for why this is
        # an explicit grant here rather than an implicit fallback.
        set_current_request(LOCAL_STDIO_REQUEST)
        mcp.run()
        return

    import uvicorn

    uvicorn.run(create_http_app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
