"""Agent-friendly setup and diagnostics for the local MCP connector."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from yunohost_mcp.auth.signing import ClientIdentity
from yunohost_mcp.bridge import BridgeConfigError, Nip98BridgeAuth, generate_key


CLIENTS = ("codex", "claude-desktop", "claude-code", "gemini", "hermes", "opencode", "openclaw")
DEFAULT_NAME = "yunohost-mcp"


def _config_root() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home()))
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def default_key_path(client: str) -> Path:
    return _config_root() / "yunohost-mcp" / f"{client}.key"


def _claude_desktop_config_path() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "Claude" / "claude_desktop_config.json"
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def config_path(client: str) -> Path:
    if client == "codex":
        return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "config.toml"
    if client == "claude-desktop":
        return _claude_desktop_config_path()
    if client == "claude-code":
        return Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home())) / ".claude.json"
    if client == "gemini":
        return Path(os.environ.get("GEMINI_HOME", Path.home() / ".gemini")) / "settings.json"
    if client == "hermes":
        return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / "config.yaml"
    if client == "opencode":
        return Path(os.environ.get("OPENCODE_CONFIG_FILE", Path.home() / ".config" / "opencode" / "opencode.json"))
    if client == "openclaw":
        return Path(os.environ.get("OPENCLAW_CONFIG_PATH", Path.home() / ".openclaw" / "openclaw.json"))
    raise BridgeConfigError(f"unknown client {client!r}; choose one of {', '.join(CLIENTS)}")


def _server_config(key_file: Path, remote_url: str) -> dict[str, Any]:
    return {
        "command": "uvx",
        "args": ["--from", "yunohost-mcp-connect", "yunohost-mcp-connect"],
        "env": {
            "YUNOHOST_MCP_CLIENT_REMOTE_URL": remote_url,
            "YUNOHOST_MCP_CLIENT_KEY_FILE": str(key_file),
        },
    }


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(path.name + ".yunohost-mcp-backup")
    if backup.exists():
        index = 1
        while path.with_name(f"{path.name}.yunohost-mcp-backup.{index}").exists():
            index += 1
        backup = path.with_name(f"{path.name}.yunohost-mcp-backup.{index}")
    shutil.copy2(path, backup)
    return backup


def _write_json_config(path: Path, name: str, server: dict[str, Any], *, print_only: bool) -> dict[str, Any]:
    current: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise BridgeConfigError(f"cannot read JSON configuration {path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise BridgeConfigError(f"JSON configuration {path} must contain an object")
        current = loaded
    servers = current.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise BridgeConfigError(f"mcpServers in {path} is not an object")
    changed = servers.get(name) != server
    if name in servers and servers[name] != server:
        raise BridgeConfigError(f"MCP server {name!r} already exists with a different configuration in {path}")
    servers[name] = server
    if not print_only and changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup = _backup(path)
        path.write_text(json.dumps(current, indent=2) + "\n")
    else:
        backup = None
    return {"path": str(path), "written": not print_only, "changed": changed, "backup": str(backup) if backup else None}


def _toml_quote(value: str) -> str:
    return json.dumps(value)


def _write_codex_config(path: Path, name: str, server: dict[str, Any], *, print_only: bool) -> dict[str, Any]:
    existing = path.read_text() if path.exists() else ""
    section = f"[mcp_servers.{name}]"
    env_section = f"[mcp_servers.{name}.env]"
    section_match = re.search(rf"(?m)^\[mcp_servers\.{re.escape(name)}\]\s*$", existing)
    changed = section_match is None
    if section_match is None:
        block = (
            f"\n{section}\n"
            "command = \"uvx\"\n"
            'args = ["--from", "yunohost-mcp-connect", "yunohost-mcp-connect"]\n\n'
            f"{env_section}\n"
            f"YUNOHOST_MCP_CLIENT_REMOTE_URL = {_toml_quote(server['env']['YUNOHOST_MCP_CLIENT_REMOTE_URL'])}\n"
            f"YUNOHOST_MCP_CLIENT_KEY_FILE = {_toml_quote(server['env']['YUNOHOST_MCP_CLIENT_KEY_FILE'])}\n"
        )
        updated = existing.rstrip() + block
    else:
        start = section_match.start()
        next_match = re.search(rf"\n\[(?!mcp_servers\.{re.escape(name)}\.)", existing[section_match.end() :])
        next_section = section_match.end() + next_match.start() if next_match else -1
        current_block = existing[start : next_section if next_section >= 0 else len(existing)]
        expected_lines = (
            'command = "uvx"',
            'args = ["--from", "yunohost-mcp-connect", "yunohost-mcp-connect"]',
            f"{env_section}",
            f"YUNOHOST_MCP_CLIENT_REMOTE_URL = {_toml_quote(server['env']['YUNOHOST_MCP_CLIENT_REMOTE_URL'])}",
            f"YUNOHOST_MCP_CLIENT_KEY_FILE = {_toml_quote(server['env']['YUNOHOST_MCP_CLIENT_KEY_FILE'])}",
        )
        if not all(line in current_block for line in expected_lines):
            raise BridgeConfigError(f"MCP server {name!r} already exists with a different configuration in {path}")
        updated = existing
    if not print_only and changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup = _backup(path)
        path.write_text(updated)
    else:
        backup = None
    return {"path": str(path), "written": not print_only, "changed": changed, "backup": str(backup) if backup else None}


def _yaml_block(name: str, server: dict[str, Any]) -> str:
    env = server["env"]
    return (
        f"  {name}:\n"
        "    command: uvx\n"
        "    args: [\"--from\", \"yunohost-mcp-connect\", \"yunohost-mcp-connect\"]\n"
        "    env:\n"
        f"      YUNOHOST_MCP_CLIENT_REMOTE_URL: {json.dumps(env['YUNOHOST_MCP_CLIENT_REMOTE_URL'])}\n"
        f"      YUNOHOST_MCP_CLIENT_KEY_FILE: {json.dumps(env['YUNOHOST_MCP_CLIENT_KEY_FILE'])}\n"
    )


def _write_hermes_config(path: Path, name: str, server: dict[str, Any], *, print_only: bool) -> dict[str, Any]:
    existing = path.read_text() if path.exists() else ""
    block = _yaml_block(name, server)
    lines = existing.splitlines(keepends=True)
    section_index = next((i for i, line in enumerate(lines) if line.strip() == "mcp_servers:"), None)
    if section_index is not None:
        section_end = len(lines)
        for index in range(section_index + 1, len(lines)):
            if lines[index].strip() and not lines[index][0].isspace():
                section_end = index
                break
        section_text = "".join(lines[section_index:section_end])
        if f"  {name}:" in section_text:
            raise BridgeConfigError(f"MCP server {name!r} already exists in {path}; edit it or choose another --name")
        lines[section_end:section_end] = [block]
        updated = "".join(lines)
    else:
        updated = existing.rstrip() + ("\n\n" if existing.strip() else "") + "mcp_servers:\n" + block
    if not print_only:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup = _backup(path)
        path.write_text(updated + ("\n" if not updated.endswith("\n") else ""))
    else:
        backup = None
    return {"path": str(path), "written": not print_only, "changed": True, "backup": str(backup) if backup else None}


def _write_opencode_config(path: Path, name: str, server: dict[str, Any], *, print_only: bool) -> dict[str, Any]:
    current: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise BridgeConfigError(f"cannot read JSON configuration {path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise BridgeConfigError(f"JSON configuration {path} must contain an object")
        current = loaded
    mcp = current.setdefault("mcp", {})
    if not isinstance(mcp, dict):
        raise BridgeConfigError(f"mcp in {path} is not an object")
    servers = mcp.setdefault("servers", {})
    if not isinstance(servers, dict):
        raise BridgeConfigError(f"mcp.servers in {path} is not an object")
    entry = {
        "type": "local",
        "command": ["uvx", "--from", "yunohost-mcp-connect", "yunohost-mcp-connect"],
        "environment": {
            "YUNOHOST_MCP_CLIENT_REMOTE_URL": server["env"]["YUNOHOST_MCP_CLIENT_REMOTE_URL"],
            "YUNOHOST_MCP_CLIENT_KEY_FILE": server["env"]["YUNOHOST_MCP_CLIENT_KEY_FILE"],
        },
    }
    if name in servers and servers[name] != entry:
        raise BridgeConfigError(f"MCP server {name!r} already exists with a different configuration in {path}")
    changed = servers.get(name) != entry
    servers[name] = entry
    if not print_only and changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup = _backup(path)
        path.write_text(json.dumps(current, indent=2) + "\n")
    else:
        backup = None
    return {"path": str(path), "written": not print_only, "changed": changed, "backup": str(backup) if backup else None}


def _write_openclaw_config(path: Path, name: str, server: dict[str, Any], *, print_only: bool) -> dict[str, Any]:
    current: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise BridgeConfigError(f"cannot read JSON configuration {path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise BridgeConfigError(f"JSON configuration {path} must contain an object")
        current = loaded
    mcp = current.setdefault("mcp", {})
    if not isinstance(mcp, dict):
        raise BridgeConfigError(f"mcp in {path} is not an object")
    servers = mcp.setdefault("servers", {})
    if not isinstance(servers, dict):
        raise BridgeConfigError(f"mcp.servers in {path} is not an object")
    entry = {
        "command": "uvx",
        "args": ["--from", "yunohost-mcp-connect", "yunohost-mcp-connect"],
        "env": {
            "YUNOHOST_MCP_CLIENT_REMOTE_URL": server["env"]["YUNOHOST_MCP_CLIENT_REMOTE_URL"],
            "YUNOHOST_MCP_CLIENT_KEY_FILE": server["env"]["YUNOHOST_MCP_CLIENT_KEY_FILE"],
        },
    }
    if name in servers and servers[name] != entry:
        raise BridgeConfigError(f"MCP server {name!r} already exists with a different configuration in {path}")
    changed = servers.get(name) != entry
    servers[name] = entry
    if not print_only and changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup = _backup(path)
        path.write_text(json.dumps(current, indent=2) + "\n")
    else:
        backup = None
    return {"path": str(path), "written": not print_only, "changed": changed, "backup": str(backup) if backup else None}


def write_client_config(client: str, name: str, key_file: Path, remote_url: str, *, print_only: bool) -> dict[str, Any]:
    server = _server_config(key_file, remote_url)
    path = config_path(client)
    if client in {"claude-desktop", "claude-code"}:
        return _write_json_config(path, name, server, print_only=print_only)
    if client == "gemini":
        return _write_json_config(path, name, server, print_only=print_only)
    if client == "codex":
        return _write_codex_config(path, name, server, print_only=print_only)
    if client == "opencode":
        return _write_opencode_config(path, name, server, print_only=print_only)
    if client == "openclaw":
        return _write_openclaw_config(path, name, server, print_only=print_only)
    return _write_hermes_config(path, name, server, print_only=print_only)


def _result(status: str, **values: Any) -> dict[str, Any]:
    return {"status": status, **values}


def _prompt_client() -> str:
    print("Which MCP client should be configured?", file=sys.stderr)
    for index, client in enumerate(CLIENTS, start=1):
        print(f"  {index}. {client}", file=sys.stderr)
    while True:
        answer = input(f"Client [1-{len(CLIENTS)}]: ").strip().lower()
        if answer.isdigit() and 1 <= int(answer) <= len(CLIENTS):
            return CLIENTS[int(answer) - 1]
        if answer in CLIENTS:
            return answer
        print(f"Choose a number from 1 to {len(CLIENTS)}, or one of: {', '.join(CLIENTS)}", file=sys.stderr)


def _prompt_server() -> str:
    while True:
        answer = input("YunoHost MCP server URL: ").strip()
        if answer.startswith(("http://", "https://")):
            return answer
        print("The server URL must start with http:// or https://", file=sys.stderr)


def setup(args: argparse.Namespace) -> int:
    if args.non_interactive and (not args.client or not args.server):
        raise BridgeConfigError("--non-interactive requires both --server and --client")
    client = args.client or _prompt_client()
    remote_url = args.server or _prompt_server()
    key_file = Path(args.key_file).expanduser() if args.key_file else default_key_path(client)
    generated = False
    if key_file.exists():
        try:
            identity = ClientIdentity.from_key_string(key_file.read_text().strip())
        except (OSError, ValueError) as exc:
            raise BridgeConfigError(f"cannot load key file {key_file}: {exc}") from exc
    else:
        identity = generate_key(key_file)
        generated = True
    config = write_client_config(client, args.name, key_file, remote_url, print_only=args.print_only)
    payload = _result(
        "configured" if not generated and not config.get("changed", True) else "awaiting_enrollment",
        client=client,
        server=remote_url,
        name=args.name,
        npub=identity.npub,
        key_file=str(key_file),
        generated_key=generated,
        enrollment_required=True,
        configuration=config,
        doctor_command=f"uvx --from yunohost-mcp-connect yunohost-mcp-connect doctor --server {remote_url} --key-file {key_file} --format json",
        next_action="Grant this npub the desired role in the server identity configuration, then restart or reload the MCP client and run doctor.",
    )
    emit(payload, args.format)
    return 0


async def _doctor_remote(remote_url: str, key_file: Path) -> dict[str, Any]:
    try:
        identity = ClientIdentity.from_key_string(key_file.read_text().strip())
    except Exception as exc:  # noqa: BLE001 - turn local errors into stable diagnostics
        return {"status": "local_invalid_key", "error": str(exc)}
    try:
        auth = Nip98BridgeAuth(identity)
        async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(30.0)) as http_client:
            transport = streamable_http_client(remote_url, http_client=http_client)
            async with Client(transport) as remote:
                who = await remote.call_tool("whoami", {})
                if who.is_error:
                    return {"status": "identity_not_enrolled", "error": "server rejected whoami"}
                if who.structured_content and who.structured_content.get("authenticated") is False:
                    return {"status": "identity_not_enrolled", "error": "server did not authenticate the client identity"}
                tools = await remote.list_tools()
                resources = await remote.list_resources()
                server_identity = await remote.call_tool("server_identity", {})
                if server_identity.is_error or not server_identity.structured_content:
                    return {"status": "mcp_protocol_failure", "error": "server_identity did not return server identity"}
                return {
                    "status": "healthy",
                    "npub": identity.npub,
                    "tool_count": len(tools.tools),
                    "resource_count": len(resources.resources),
                    "server_npub": server_identity.structured_content.get("npub"),
                    "authenticated": who.structured_content.get("authenticated", True) if who.structured_content else True,
                }
    except httpx2.HTTPError as exc:
        return {"status": "network_failure", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - diagnostics must remain machine-readable
        return {"status": "mcp_protocol_failure", "error": str(exc)}


def doctor(args: argparse.Namespace) -> int:
    key_file = Path(args.key_file).expanduser()
    if not key_file.exists():
        payload = {"status": "local_missing_key", "key_file": str(key_file)}
    else:
        mode = stat.S_IMODE(key_file.stat().st_mode)
        if os.name != "nt" and mode & 0o077:
            payload = {"status": "local_insecure_key_permissions", "key_file": str(key_file), "mode": oct(mode)}
        else:
            payload = asyncio.run(_doctor_remote(args.server, key_file))
            payload["key_file"] = str(key_file)
            payload["server"] = args.server
    emit(payload, args.format)
    return 0 if payload["status"] == "healthy" else 1


def emit(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"yunohost-mcp-connect: {payload['status']}")
    for key, value in payload.items():
        if key != "status":
            print(f"  {key}: {value}")


def add_setup_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("setup", help="generate a key and configure an MCP client")
    parser.add_argument("--server", help="remote YunoHost MCP endpoint")
    parser.add_argument("--client", choices=CLIENTS)
    parser.add_argument("--key-file")
    parser.add_argument("--name", default=DEFAULT_NAME)
    parser.add_argument("--print-only", action="store_true")
    parser.add_argument("--non-interactive", action="store_true", help="accepted for agent automation")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.set_defaults(handler=setup)


def add_doctor_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("doctor", help="diagnose the local key and remote MCP connection")
    parser.add_argument("--server", required=True, help="remote YunoHost MCP endpoint")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.set_defaults(handler=doctor)
