"""yunohost-mcp server.

Phase 1: minimal MCP foundation, stdio transport.
Phase 2: adds a Streamable HTTP transport wrapped in NIP-98 authentication
(auth/middleware.py) — a valid signature establishes identity (whoami), but
does not yet authorize anything; every validly-signed request can call every
tool until Phase 3's pubkey->role/scope mapping lands. `server_info` and
`health_check` remain the only real tools; the rest of PLAN.md's v0.1 scope
follows once auth+policy are both in place.
"""

from __future__ import annotations

import argparse
from typing import Any

from mcp.server.mcpserver import MCPServer

from yunohost_mcp.auth.identity import get_current_identity
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.config import load_settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter

settings = load_settings()
adapter = YunohostAdapter(settings=settings)

mcp = MCPServer(settings.server_name)


@mcp.tool()
def server_info() -> dict[str, Any]:
    """Return YunoHost server/component version information."""
    return adapter.server_info()


@mcp.tool()
def health_check() -> dict[str, Any]:
    """Return a summary YunoHost diagnosis report."""
    return adapter.health_check()


@mcp.tool()
def whoami() -> dict[str, Any]:
    """Return the Nostr identity that authenticated the current request.

    Only meaningful over the HTTP transport (auth/middleware.py); over
    stdio there is no NIP-98 handshake, so this returns null.
    """
    identity = get_current_identity()
    if identity is None:
        return {"authenticated": False, "pubkey": None}
    return {"authenticated": True, "pubkey": identity.pubkey, "event_id": identity.event_id}


def create_http_app():
    """Build the ASGI app for the Streamable HTTP transport: MCP wrapped in NIP-98 auth."""
    inner_app = mcp.streamable_http_app()
    return NostrAuthMiddleware(
        inner_app,
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
        mcp.run()
        return

    import uvicorn

    uvicorn.run(create_http_app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
