"""yunohost-mcp-connect: a local stdio<->remote-HTTP bridge that signs every
outgoing request with NIP-98, so a mainstream MCP client (Claude Desktop,
Codex, or anything else that can launch a local stdio subprocess) can talk
to a yunohost-mcp server without knowing anything about Nostr itself.

Mainstream MCP clients have no way to attach a custom `Authorization: Nostr
...` header to a remote HTTP connection - the standard integration point
they *do* support is "run this local command and speak MCP over its
stdin/stdout". This bridge is exactly that: a real local MCP server on one
side, a real MCP client to the actual remote server on the other, with
every request signed in between. It does not reimplement or wrap any tool
locally - `tools/list`, `tools/call`, `resources/list`, and
`resources/read` are forwarded to the remote server's own handlers
verbatim (auth/identity/policy/audit all still happen server-side, exactly
as if the client had signed the request itself, because in a very real
sense it did - the private key never leaves this process).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import anyio
import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolRequestParams, PaginatedRequestParams, ReadResourceRequestParams

from yunohost_mcp.auth.signing import ClientIdentity, KeyLoadError


class BridgeConfigError(ValueError):
    """Missing or invalid --remote-url/--key/--key-file for the bridge."""


class Nip98BridgeAuth(httpx2.Auth):
    """Signs every outgoing request with this client's own NIP-98 event,
    and attaches a pre-signed delegation event (if configured) alongside
    it - the delegation is presented, never signed here; it was signed
    ahead of time by whoever granted it (auth/delegation.py, server side)."""

    def __init__(self, identity: ClientIdentity, delegation_header: str | None = None) -> None:
        self.identity = identity
        self.delegation_header = delegation_header

    def auth_flow(self, request):  # noqa: ANN001 - httpx2's own Request type, not worth importing just to annotate
        body = request.content or b""
        request.headers["Authorization"] = self.identity.sign_nip98(
            method=request.method, url=str(request.url), body=body
        )
        if self.delegation_header:
            request.headers["X-Nostr-Delegation"] = self.delegation_header
        yield request


def load_identity(args: argparse.Namespace) -> ClientIdentity:
    key = args.key or os.environ.get("YUNOHOST_MCP_CLIENT_KEY")
    key_file = args.key_file or os.environ.get("YUNOHOST_MCP_CLIENT_KEY_FILE")

    if key_file:
        key = Path(key_file).read_text().strip()
    if not key:
        raise BridgeConfigError(
            "no private key given - pass --key/--key-file, or set "
            "YUNOHOST_MCP_CLIENT_KEY/YUNOHOST_MCP_CLIENT_KEY_FILE. A key file is preferred: "
            "--key/YUNOHOST_MCP_CLIENT_KEY put a private key in a process's argv/environment, "
            "both readable by anything else running as this user."
        )
    try:
        return ClientIdentity.from_key_string(key)
    except KeyLoadError as exc:
        raise BridgeConfigError(str(exc)) from exc


def _load_delegation_header(args: argparse.Namespace) -> str | None:
    """A delegation is presented as-is (base64 of the exact signed event
    JSON) - this bridge never constructs or signs one; auth/delegation.py's
    verify_delegation_event() on the server side does all the checking."""
    import base64

    delegation_file = args.delegation_file or os.environ.get("YUNOHOST_MCP_CLIENT_DELEGATION_FILE")
    if not delegation_file:
        return None
    raw = Path(delegation_file).read_bytes()
    return base64.b64encode(raw).decode()


def _build_local_server(remote: Client, *, name: str) -> MCPServer:
    """A local MCPServer whose tools/resources handlers forward verbatim to
    the connected remote Client - see this module's own docstring for why
    a raw handler override (not per-tool registration) is the right shape
    for a proxy that doesn't know the remote tool list ahead of time."""
    local = MCPServer(name)
    lowlevel = local._lowlevel_server  # noqa: SLF001 - add_request_handler is the documented, public override point on Server; MCPServer just doesn't re-expose it itself

    async def handle_list_tools(ctx, params: PaginatedRequestParams | None):
        return await remote.list_tools(cursor=params.cursor if params else None)

    async def handle_call_tool(ctx, params: CallToolRequestParams):
        return await remote.call_tool(params.name, params.arguments or {})

    async def handle_list_resources(ctx, params: PaginatedRequestParams | None):
        return await remote.list_resources(cursor=params.cursor if params else None)

    async def handle_read_resource(ctx, params: ReadResourceRequestParams):
        return await remote.read_resource(params.uri)

    lowlevel.add_request_handler("tools/list", PaginatedRequestParams, handle_list_tools)
    lowlevel.add_request_handler("tools/call", CallToolRequestParams, handle_call_tool)
    lowlevel.add_request_handler("resources/list", PaginatedRequestParams, handle_list_resources)
    lowlevel.add_request_handler("resources/read", ReadResourceRequestParams, handle_read_resource)
    return local


async def _async_main(args: argparse.Namespace) -> None:
    identity = load_identity(args)
    delegation_header = _load_delegation_header(args)
    auth = Nip98BridgeAuth(identity, delegation_header)

    print(f"yunohost-mcp-connect: signing as {identity.npub}, connecting to {args.remote_url}", file=sys.stderr)

    async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(120.0)) as http_client:
        transport = streamable_http_client(args.remote_url, http_client=http_client)
        async with Client(transport) as remote:
            local = _build_local_server(remote, name=args.name)
            await local.run_stdio_async()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="yunohost-mcp-connect",
        description="Bridge a mainstream MCP client (stdio) to a remote yunohost-mcp server (NIP-98 over HTTP).",
    )
    parser.add_argument(
        "--remote-url",
        default=os.environ.get("YUNOHOST_MCP_CLIENT_REMOTE_URL"),
        help="e.g. https://your-domain/mcp (or $YUNOHOST_MCP_CLIENT_REMOTE_URL)",
    )
    parser.add_argument("--key", help="hex or nsec1... private key (prefer --key-file; see $YUNOHOST_MCP_CLIENT_KEY)")
    parser.add_argument(
        "--key-file", help="path to a file containing a hex or nsec1... private key (see $YUNOHOST_MCP_CLIENT_KEY_FILE)"
    )
    parser.add_argument(
        "--delegation-file",
        help="path to a JSON delegation event to present alongside this identity's own signature "
        "(see $YUNOHOST_MCP_CLIENT_DELEGATION_FILE; PLAN.md Phase 11)",
    )
    parser.add_argument("--name", default="yunohost-mcp-bridge", help="name this local MCP server advertises")
    args = parser.parse_args()

    if not args.remote_url:
        raise BridgeConfigError("no --remote-url given, and $YUNOHOST_MCP_CLIENT_REMOTE_URL is not set")

    anyio.run(_async_main, args)


if __name__ == "__main__":
    main()
