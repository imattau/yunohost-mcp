"""yunohost-mcp Phase 1 server.

Minimal MCP foundation: stdio transport, no auth (Phase 2), no policy
(Phase 6), just enough to prove an MCP client can call into the YunoHost
adapter. `server_info` and `health_check` are the first two tools from
PLAN.md's v0.1 read-only scope; the rest land alongside the auth/policy
layers so nothing is reachable without them.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
