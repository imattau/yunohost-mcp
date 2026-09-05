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
import asyncio
import os
import secrets
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Awaitable, Callable, TypeVar

import anyio
import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp_types import (
    CallToolRequestParams,
    CallToolResult,
    ListResourcesResult,
    ListToolsResult,
    PaginatedRequestParams,
    ReadResourceRequestParams,
    TextContent,
)

from yunohost_mcp.auth.signing import ClientIdentity, KeyLoadError


class BridgeConfigError(ValueError):
    """Missing or invalid --remote-url/--key/--key-file for the bridge."""


class RemoteUnavailable(RuntimeError):
    """The configured remote MCP server could not be reached."""


_T = TypeVar("_T")


class RemoteSession:
    """Lazily connect to one remote server without making local startup fatal.

    MCP clients commonly start several stdio servers as one startup operation.
    The remote server is an optional dependency of this process, so a failed
    remote handshake must not prevent this process from completing its own
    local MCP handshake.  Requests made while the remote is unavailable get a
    useful per-request error (or an empty discovery result), and a later
    request retries the connection after a short cooldown.
    """

    RETRY_DELAY_SECONDS = 5.0

    def __init__(self, remote_url: str, http_client: httpx2.AsyncClient) -> None:
        self.remote_url = remote_url
        self.http_client = http_client
        self._remote: Client | None = None
        self._stack: AsyncExitStack | None = None
        self._state_lock = asyncio.Lock()
        self._next_retry_at = 0.0
        self._last_error: str | None = None

    async def _connect(self) -> Client:
        now = time.monotonic()
        if self._remote is not None:
            return self._remote
        if now < self._next_retry_at:
            detail = self._last_error or "connection attempt is cooling down"
            raise RemoteUnavailable(detail)

        async with self._state_lock:
            if self._remote is not None:
                return self._remote
            now = time.monotonic()
            if now < self._next_retry_at:
                detail = self._last_error or "connection attempt is cooling down"
                raise RemoteUnavailable(detail)

            stack = AsyncExitStack()
            try:
                transport = await stack.enter_async_context(
                    streamable_http_client(self.remote_url, http_client=self.http_client)
                )
                remote = await stack.enter_async_context(Client(transport))
            except Exception as exc:  # noqa: BLE001 - isolate one remote from the local MCP process
                await stack.aclose()
                self._last_error = str(exc) or exc.__class__.__name__
                self._next_retry_at = time.monotonic() + self.RETRY_DELAY_SECONDS
                self._log_unavailable()
                raise RemoteUnavailable(self._last_error) from exc

            self._stack = stack
            self._remote = remote
            self._last_error = None
            self._next_retry_at = 0.0
            print(f"yunohost-mcp-connect: connected to {self.remote_url}", file=sys.stderr)
            return remote

    async def _drop(self, remote: Client) -> None:
        async with self._state_lock:
            if self._remote is not remote:
                return
            self._remote = None
            stack = self._stack
            self._stack = None
            self._next_retry_at = time.monotonic() + self.RETRY_DELAY_SECONDS
            if stack is not None:
                await stack.aclose()

    def _log_unavailable(self) -> None:
        detail = self._last_error or "unknown connection error"
        print(
            f"yunohost-mcp-connect: remote server unavailable at {self.remote_url}; "
            f"will retry: {detail}",
            file=sys.stderr,
        )

    async def request(self, operation: Callable[[Client], Awaitable[_T]]) -> _T:
        remote = await self._connect()
        try:
            return await operation(remote)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a dead remote must not kill local MCP
            self._last_error = str(exc) or exc.__class__.__name__
            self._log_unavailable()
            await self._drop(remote)
            raise RemoteUnavailable(self._last_error) from exc

    async def close(self) -> None:
        async with self._state_lock:
            self._remote = None
            stack = self._stack
            self._stack = None
            if stack is not None:
                await stack.aclose()

    @property
    def unavailable_message(self) -> str:
        detail = self._last_error or "the connection has not been established"
        return f"YunoHost MCP server at {self.remote_url} is unavailable: {detail}"


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


def generate_key(path: Path) -> ClientIdentity:
    """Write a fresh private key to `path` (0600, refuses to overwrite an
    existing file) and return the resulting identity.

    Exists because the path of least resistance without it - copying a
    key file that already works for a different client into a new one's
    config - produces no error, no warning: whichever key signs a
    request determines its identity and permissions on the server, and
    that's ALL it determines, so a copied key file just quietly grants
    the second client the first one's exact access. Generating a
    dedicated key per client is the fix; this makes doing that no harder
    than reusing one.
    """
    if path.exists():
        raise BridgeConfigError(f"refusing to overwrite an existing key file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    # A uniformly random 32-byte value is virtually certain to already be
    # a valid secp256k1 private key (invalid only for the ~1-in-2^128
    # values outside [1, n-1]) - retrying on the practically-unreachable
    # KeyLoadError case is simpler and just as correct as reproducing
    # coincurve's own validity check here.
    while True:
        hex_key = secrets.token_bytes(32).hex()
        try:
            identity = ClientIdentity.from_key_string(hex_key)
        except KeyLoadError:
            continue
        break
    path.write_text(hex_key + "\n")
    path.chmod(0o600)
    return identity


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


def _build_local_server(remote: Client | RemoteSession, *, name: str) -> MCPServer:
    """Build a local MCPServer whose handlers forward to the remote.

    A raw handler override (not per-tool registration) is the right shape for
    a proxy that does not know the remote tool list ahead of time. ``remote``
    may be an already connected Client for compatibility, or a
    ``RemoteSession`` that connects lazily and isolates connection failures.
    """
    local = MCPServer(name)
    lowlevel = local._lowlevel_server  # noqa: SLF001 - add_request_handler is the documented, public override point on Server; MCPServer just doesn't re-expose it itself

    async def request(operation: Callable[[Client], Awaitable[_T]]) -> _T:
        # Keep this helper compatible with callers/tests that already pass a
        # connected Client, while the production bridge passes RemoteSession.
        if isinstance(remote, RemoteSession):
            return await remote.request(operation)
        return await operation(remote)

    async def handle_list_tools(ctx, params: PaginatedRequestParams | None):
        try:
            return await request(
                lambda connected: connected.list_tools(cursor=params.cursor if params else None)
            )
        except RemoteUnavailable:
            # Discovery must still complete so this connector cannot block
            # other independent MCP servers from starting.
            return ListToolsResult(tools=[])

    async def handle_call_tool(ctx, params: CallToolRequestParams):
        try:
            return await request(lambda connected: connected.call_tool(params.name, params.arguments or {}))
        except RemoteUnavailable:
            return CallToolResult(
                content=[TextContent(text=remote.unavailable_message)],
                isError=True,
            )

    async def handle_list_resources(ctx, params: PaginatedRequestParams | None):
        try:
            return await request(
                lambda connected: connected.list_resources(cursor=params.cursor if params else None)
            )
        except RemoteUnavailable:
            return ListResourcesResult(resources=[])

    async def handle_read_resource(ctx, params: ReadResourceRequestParams):
        return await request(lambda connected: connected.read_resource(params.uri))

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
        remote = RemoteSession(args.remote_url, http_client)
        local = _build_local_server(remote, name=args.name)
        try:
            await local.run_stdio_async()
        finally:
            await remote.close()


def main() -> None:
    # Keep the original flag-based bridge invocation stable for MCP clients,
    # while exposing agent-friendly lifecycle commands as subcommands.
    if len(sys.argv) > 1 and sys.argv[1] in {"setup", "doctor"}:
        from yunohost_mcp.onboarding import add_doctor_parser, add_setup_parser

        command_parser = argparse.ArgumentParser(prog="yunohost-mcp-connect")
        subparsers = command_parser.add_subparsers(dest="command", required=True)
        add_setup_parser(subparsers)
        add_doctor_parser(subparsers)
        args = command_parser.parse_args()
        raise SystemExit(args.handler(args))

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
        "--generate-key",
        metavar="PATH",
        help="write a fresh private key to PATH (0600; refuses to overwrite an existing file), print its "
        "npub, and exit without connecting anywhere - use a distinct PATH per client (Claude Desktop, "
        "Codex, ...): whichever key signs a request is that request's entire identity on the server, so "
        "reusing one client's key file for another silently gives it that client's exact permissions",
    )
    parser.add_argument(
        "--delegation-file",
        help="path to a JSON delegation event to present alongside this identity's own signature "
        "(see $YUNOHOST_MCP_CLIENT_DELEGATION_FILE; PLAN.md Phase 11)",
    )
    parser.add_argument("--name", default="yunohost-mcp-bridge", help="name this local MCP server advertises")
    args = parser.parse_args()

    if args.generate_key:
        path = Path(args.generate_key).expanduser()
        identity = generate_key(path)
        print(f"yunohost-mcp-connect: generated a new key at {path}", file=sys.stderr)
        print(f"yunohost-mcp-connect: its npub is {identity.npub}", file=sys.stderr)
        print(
            "Grant this npub whatever role is appropriate for this client in identity.toml - "
            "not the role you already gave a different client.",
            file=sys.stderr,
        )
        return

    if not args.remote_url:
        raise BridgeConfigError("no --remote-url given, and $YUNOHOST_MCP_CLIENT_REMOTE_URL is not set")

    anyio.run(_async_main, args)


if __name__ == "__main__":
    main()
