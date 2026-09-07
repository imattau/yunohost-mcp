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
import contextlib
import copy
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar
from urllib.parse import urlsplit, urlunsplit

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
    Tool,
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

    The transport's own task group must be opened and closed by the single
    task that runs it, for its whole lifetime (anyio requires this).  The
    request that triggers the first connect is itself running inside a
    per-request cancel scope - every MCP dispatcher wraps request handling in
    `anyio.fail_after(...)` - that closes long before the connection should,
    so the connect/hold/close cycle cannot happen inline in `_connect()`.
    Instead it runs start to finish in one dedicated task spawned onto
    `task_group`, a task group owned and entered once by the caller
    (`_async_main`) outside of any request handling; `_connect()` only ever
    calls `task_group.start_soon(...)`, which - unlike entering a task group -
    is safe to call from any task, including from inside that request's
    `fail_after` scope.
    """

    RETRY_DELAY_SECONDS = 5.0

    def __init__(self, remote_url: str, http_client: httpx2.AsyncClient, task_group: anyio.abc.TaskGroup) -> None:
        self.remote_url = remote_url
        self.http_client = http_client
        self._task_group = task_group
        self._remote: Client | None = None
        self._close_event: anyio.Event | None = None
        self._state_lock = asyncio.Lock()
        self._next_retry_at = 0.0
        self._last_error: str | None = None

    async def _run_connection(self, ready: anyio.Event, close_event: anyio.Event) -> None:
        """Owns the transport's connect/hold/close cycle in one task, start to finish."""
        try:
            transport = streamable_http_client(self.remote_url, http_client=self.http_client)
            async with Client(transport) as remote:
                self._remote = remote
                self._last_error = None
                ready.set()
                await close_event.wait()
        except anyio.get_cancelled_exc_class():
            raise
        except Exception as exc:  # noqa: BLE001 - isolate one remote from the local MCP process
            self._last_error = str(exc) or exc.__class__.__name__
            ready.set()
        finally:
            self._remote = None

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

            ready = anyio.Event()
            close_event = anyio.Event()
            self._close_event = close_event
            self._task_group.start_soon(self._run_connection, ready, close_event)
            await ready.wait()

            if self._remote is None:
                self._close_event = None
                self._next_retry_at = time.monotonic() + self.RETRY_DELAY_SECONDS
                self._log_unavailable()
                raise RemoteUnavailable(self._last_error or "unknown connection error")

            self._next_retry_at = 0.0
            print(f"yunohost-mcp-connect: connected to {self.remote_url}", file=sys.stderr)
            return self._remote

    async def _drop(self, remote: Client) -> None:
        async with self._state_lock:
            if self._remote is not remote:
                return
            self._remote = None
            self._next_retry_at = time.monotonic() + self.RETRY_DELAY_SECONDS
            if self._close_event is not None:
                self._close_event.set()
                self._close_event = None

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
            if self._close_event is not None:
                self._close_event.set()
                self._close_event = None

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


def load_identity_from_key_file(key_file: Path) -> ClientIdentity:
    key = Path(key_file).read_text().strip()
    try:
        return ClientIdentity.from_key_string(key)
    except KeyLoadError as exc:
        raise BridgeConfigError(str(exc)) from exc


def load_identity(args: argparse.Namespace) -> ClientIdentity:
    key = args.key or os.environ.get("YUNOHOST_MCP_CLIENT_KEY")
    key_file = args.key_file or os.environ.get("YUNOHOST_MCP_CLIENT_KEY_FILE")

    if key_file:
        return load_identity_from_key_file(Path(key_file))
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


def _prefix_resource_uri(host: str, uri: str) -> str:
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme, f"{host}.{parts.netloc}", parts.path, parts.query, parts.fragment))


def _split_resource_uri(uri: str) -> tuple[str, str]:
    """Inverse of `_prefix_resource_uri`: returns (host, original_uri)."""
    parts = urlsplit(uri)
    host, _, original_netloc = parts.netloc.partition(".")
    if not original_netloc:
        raise KeyError(f"resource URI {uri!r} is not host-prefixed")
    original = urlunsplit((parts.scheme, original_netloc, parts.path, parts.query, parts.fragment))
    return host, original


#: How often the multi-host bridge re-polls every host's tool list in the
#: background, purely to notice a previously-down host coming back (or vice
#: versa) and push `notifications/tools/list_changed` - independent of, and
#: much less frequent than, whatever polling a connected client does itself.
TOOL_POLL_INTERVAL_SECONDS = 30.0


async def _collect_tools_by_host(sessions: dict[str, RemoteSession]) -> dict[str, dict[str, Tool]]:
    tools_by_host: dict[str, dict[str, Tool]] = {}
    for host, session in sessions.items():
        try:
            result = await session.request(lambda connected: connected.list_tools())
        except RemoteUnavailable:
            continue
        for tool in result.tools:
            tools_by_host.setdefault(tool.name, {})[host] = tool
    return tools_by_host


def _merge_tools(tools_by_host: dict[str, dict[str, Tool]]) -> list[Tool]:
    merged: list[Tool] = []
    for tool_name, by_host in tools_by_host.items():
        hosts_for_tool = sorted(by_host)
        reference_host = hosts_for_tool[0]
        reference = by_host[reference_host]
        schemas_differ = any(by_host[h].input_schema != reference.input_schema for h in hosts_for_tool[1:])
        if schemas_differ:
            print(
                f"yunohost-mcp-connect: tool {tool_name!r} has a different schema on "
                f"{hosts_for_tool} - merging using {reference_host}'s schema",
                file=sys.stderr,
            )
        schema = copy.deepcopy(reference.input_schema)
        schema.setdefault("properties", {})["host"] = {
            "type": "string",
            "enum": hosts_for_tool,
            "description": "Which YunoHost server to run this tool on.",
        }
        required = schema.setdefault("required", [])
        if "host" not in required:
            required.append("host")
        merged.append(
            Tool(
                name=tool_name,
                description=reference.description,
                input_schema=schema,
                output_schema=reference.output_schema,
            )
        )
    return merged


def _host_signature(tools_by_host: dict[str, dict[str, Tool]]) -> dict[str, tuple[str, ...]]:
    """A cheap fingerprint of which hosts serve which tools - enough to tell
    whether a background poll should push tools/list_changed, without caring
    about description/schema text changes that don't affect the `host` enum."""
    return {name: tuple(sorted(by_host)) for name, by_host in tools_by_host.items()}


def _build_multi_host_local_server(sessions: dict[str, RemoteSession], *, name: str) -> MCPServer:
    """Bridge several remote yunohost-mcp servers as one local MCP server.

    Tools that exist on more than one host are merged into a single tool
    definition with a `host` parameter added to its schema, so a mainstream
    MCP client sees each distinct capability once instead of once per host -
    the whole point of multi-host mode. `resources/*` URIs are disambiguated
    by splicing the host name into the URI's netloc instead (resources take
    no arguments to add a `host` field to).

    The returned `MCPServer` also carries a `_poll_for_host_changes`
    coroutine function (stashed as an attribute, since `MCPServer` has no
    extension point for a caller-supplied background task): `_async_main_multi_host`
    starts it in the same task group as the `RemoteSession`s so a host
    recovering or dropping mid-session pushes `tools/list_changed` instead of
    silently waiting for the next client-initiated `tools/list` call.
    """
    local = MCPServer(name)
    lowlevel = local._lowlevel_server  # noqa: SLF001 - see _build_local_server's note on this being the documented override point

    # tool_name -> {host_name: Tool}, refreshed on every tools/list (and by
    # the background poller) so a newly-appeared or newly-unavailable host is
    # reflected without a restart.
    _tools_by_host: dict[str, dict[str, Tool]] = {}
    _current_session: list[Any] = [None]  # mutable box: closures below fill this in on any request

    async def handle_list_tools(ctx, params: PaginatedRequestParams | None):
        _current_session[0] = ctx.session
        _tools_by_host.clear()
        _tools_by_host.update(await _collect_tools_by_host(sessions))
        return ListToolsResult(tools=_merge_tools(_tools_by_host))

    async def handle_call_tool(ctx, params: CallToolRequestParams):
        _current_session[0] = ctx.session
        arguments = dict(params.arguments or {})
        hosts_for_tool = sorted(_tools_by_host.get(params.name, {}))
        host = arguments.pop("host", None)
        if host is None:
            return CallToolResult(
                content=[
                    TextContent(
                        text=f"tool {params.name!r} requires a 'host' argument: one of {hosts_for_tool}"
                    )
                ],
                isError=True,
            )
        if host not in hosts_for_tool:
            return CallToolResult(
                content=[
                    TextContent(
                        text=f"unknown host {host!r} for tool {params.name!r}: valid hosts are {hosts_for_tool}"
                    )
                ],
                isError=True,
            )
        session = sessions[host]
        try:
            return await session.request(lambda connected: connected.call_tool(params.name, arguments))
        except RemoteUnavailable:
            return CallToolResult(content=[TextContent(text=session.unavailable_message)], isError=True)

    async def handle_list_resources(ctx, params: PaginatedRequestParams | None):
        _current_session[0] = ctx.session
        resources = []
        for host, session in sessions.items():
            try:
                result = await session.request(
                    lambda connected: connected.list_resources(cursor=params.cursor if params else None)
                )
            except RemoteUnavailable:
                continue
            for resource in result.resources:
                resources.append(resource.model_copy(update={"uri": _prefix_resource_uri(host, str(resource.uri))}))
        return ListResourcesResult(resources=resources)

    async def handle_read_resource(ctx, params: ReadResourceRequestParams):
        _current_session[0] = ctx.session
        host, original_uri = _split_resource_uri(str(params.uri))
        session = sessions[host]
        return await session.request(lambda connected: connected.read_resource(original_uri))

    lowlevel.add_request_handler("tools/list", PaginatedRequestParams, handle_list_tools)
    lowlevel.add_request_handler("tools/call", CallToolRequestParams, handle_call_tool)
    lowlevel.add_request_handler("resources/list", PaginatedRequestParams, handle_list_resources)
    lowlevel.add_request_handler("resources/read", ReadResourceRequestParams, handle_read_resource)

    async def poll_for_host_changes() -> None:
        last_signature = _host_signature(await _collect_tools_by_host(sessions))
        while True:
            await anyio.sleep(TOOL_POLL_INTERVAL_SECONDS)
            try:
                tools_by_host = await _collect_tools_by_host(sessions)
            except anyio.get_cancelled_exc_class():
                raise
            except Exception as exc:  # noqa: BLE001 - a poll failure must not kill the bridge
                print(f"yunohost-mcp-connect: background tool-list poll failed: {exc}", file=sys.stderr)
                continue

            signature = _host_signature(tools_by_host)
            if signature == last_signature:
                continue
            last_signature = signature
            _tools_by_host.clear()
            _tools_by_host.update(tools_by_host)
            print("yunohost-mcp-connect: host availability changed, notifying client", file=sys.stderr)
            session = _current_session[0]
            if session is None:
                continue
            try:
                await session.send_tool_list_changed()
            except anyio.get_cancelled_exc_class():
                raise
            except Exception as exc:  # noqa: BLE001 - a dead/detached client session must not kill the poller
                print(f"yunohost-mcp-connect: failed to notify client of tool list change: {exc}", file=sys.stderr)

    local._poll_for_host_changes = poll_for_host_changes  # noqa: SLF001 - see docstring: stashed for _async_main_multi_host
    return local


async def _async_main(args: argparse.Namespace) -> None:
    identity = load_identity(args)
    delegation_header = _load_delegation_header(args)
    auth = Nip98BridgeAuth(identity, delegation_header)

    print(f"yunohost-mcp-connect: signing as {identity.npub}, connecting to {args.remote_url}", file=sys.stderr)

    async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(120.0)) as http_client:
        async with anyio.create_task_group() as task_group:
            remote = RemoteSession(args.remote_url, http_client, task_group)
            local = _build_local_server(remote, name=args.name)
            try:
                await local.run_stdio_async()
            finally:
                await remote.close()


async def _async_main_multi_host(args: argparse.Namespace) -> None:
    from yunohost_mcp.hosts import load_hosts_file

    hosts = load_hosts_file(Path(args.hosts_file))

    async with contextlib.AsyncExitStack() as stack:
        async with anyio.create_task_group() as task_group:
            sessions: dict[str, RemoteSession] = {}
            for host in hosts:
                identity = load_identity_from_key_file(host.key_file)
                auth = Nip98BridgeAuth(identity)
                print(
                    f"yunohost-mcp-connect: signing as {identity.npub} for host {host.name!r}, "
                    f"connecting to {host.remote_url}",
                    file=sys.stderr,
                )
                http_client = await stack.enter_async_context(
                    httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(120.0))
                )
                sessions[host.name] = RemoteSession(host.remote_url, http_client, task_group)

            local = _build_multi_host_local_server(sessions, name=args.name)
            task_group.start_soon(local._poll_for_host_changes)  # noqa: SLF001 - see _build_multi_host_local_server's docstring
            try:
                await local.run_stdio_async()
            finally:
                for session in sessions.values():
                    await session.close()
                # poll_for_host_changes loops forever by design - cancel it (and
                # anything else left in this task group) so the group's
                # __aexit__ doesn't hang once the client disconnects and the
                # stdio handshake is over.
                task_group.cancel_scope.cancel()


def main() -> None:
    # Keep the original flag-based bridge invocation stable for MCP clients,
    # while exposing agent-friendly lifecycle commands as subcommands.
    if len(sys.argv) > 1 and sys.argv[1] in {"setup", "doctor", "migrate", "hosts"}:
        from yunohost_mcp.onboarding import add_doctor_parser, add_hosts_parser, add_migrate_parser, add_setup_parser

        command_parser = argparse.ArgumentParser(prog="yunohost-mcp-connect")
        subparsers = command_parser.add_subparsers(dest="command", required=True)
        add_setup_parser(subparsers)
        add_doctor_parser(subparsers)
        add_migrate_parser(subparsers)
        add_hosts_parser(subparsers)
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
    parser.add_argument(
        "--hosts-file",
        default=os.environ.get("YUNOHOST_MCP_CLIENT_HOSTS_FILE"),
        help="path to a TOML file listing multiple [[host]] servers to bridge at once, each with its own "
        "name/remote_url/key_file (or $YUNOHOST_MCP_CLIENT_HOSTS_FILE) - mutually exclusive with --remote-url; "
        "merges same-named tools across hosts into one tool with an added 'host' argument",
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

    if args.hosts_file:
        if args.remote_url:
            raise BridgeConfigError("--hosts-file and --remote-url are mutually exclusive")
        anyio.run(_async_main_multi_host, args)
        return

    if not args.remote_url:
        raise BridgeConfigError("no --remote-url given, and $YUNOHOST_MCP_CLIENT_REMOTE_URL is not set")

    anyio.run(_async_main, args)


if __name__ == "__main__":
    main()
