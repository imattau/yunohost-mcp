"""Agent-friendly setup and diagnostics for the local MCP connector."""

from __future__ import annotations

import argparse
import asyncio
import copy
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


# Clients whose config is a plain JSON dict of server entries, so migrate()
# can read/rewrite it in memory instead of doing regex text surgery like
# _write_codex_config/_write_hermes_config do for their non-JSON formats.
_JSON_CLIENTS = ("claude-desktop", "claude-code", "gemini", "opencode", "openclaw")


def _servers_dict(client: str, current: dict[str, Any]) -> dict[str, Any]:
    if client in {"claude-desktop", "claude-code", "gemini"}:
        servers = current.setdefault("mcpServers", {})
    elif client in {"opencode", "openclaw"}:
        servers = current.setdefault("mcp", {}).setdefault("servers", {})
    else:
        raise BridgeConfigError(f"migrate does not support client {client!r} yet - edit its config by hand")
    if not isinstance(servers, dict):
        raise BridgeConfigError(f"server list for {client!r} in its config is not an object")
    return servers


def _entry_env(entry: dict[str, Any]) -> dict[str, Any] | None:
    env = entry.get("env")
    if not isinstance(env, dict):
        env = entry.get("environment")
    return env if isinstance(env, dict) else None


def _entry_is_yunohost_mcp_connect(entry: dict[str, Any]) -> bool:
    """True for an entry shaped like write_client_config's own output: run
    via `uvx --from yunohost-mcp-connect yunohost-mcp-connect` or a direct
    path to the `yunohost-mcp-connect` binary (opencode's `command` is a
    list; every other client's is a bare string)."""
    command = entry.get("command")
    args: list[Any] = entry.get("args") if isinstance(entry.get("args"), list) else []
    if isinstance(command, list):
        args = command[1:]
        command = command[0] if command else None
    if not isinstance(command, str):
        return False
    if Path(command).name == "yunohost-mcp-connect":
        return True
    return Path(command).name in {"uvx", "uv"} and any("yunohost-mcp-connect" in str(a) for a in args)


def _find_single_host_entries(servers: dict[str, Any]) -> dict[str, tuple[str, str, dict[str, Any]]]:
    """server-entry-name -> (remote_url, key_file, entry) for every entry
    that looks like a single-host `setup`-generated yunohost-mcp-connect
    config (not already in hosts-file mode)."""
    found: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict) or not _entry_is_yunohost_mcp_connect(entry):
            continue
        env = _entry_env(entry)
        if not env or env.get("YUNOHOST_MCP_CLIENT_HOSTS_FILE"):
            continue
        remote_url = env.get("YUNOHOST_MCP_CLIENT_REMOTE_URL")
        key_file = env.get("YUNOHOST_MCP_CLIENT_KEY_FILE")
        if not remote_url or not key_file:
            continue
        found[name] = (remote_url, key_file, entry)
    return found


def _sanitize_host_name(name: str) -> str:
    """Host names get spliced into resource URIs (see bridge.py's multi-host
    mode) and can't contain '.'; collapse anything unsuitable to '-'."""
    sanitized = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")
    return sanitized or "host"


def _build_migrated_entry(client: str, reference_entry: dict[str, Any], hosts_file: Path) -> dict[str, Any]:
    """Keep the reference entry's own command/args (whichever invocation
    style - uvx or a pinned binary path - the user's config already uses)
    and swap its env for hosts-file mode."""
    entry = copy.deepcopy(reference_entry)
    env_key = "environment" if client == "opencode" else "env"
    entry[env_key] = {"YUNOHOST_MCP_CLIENT_HOSTS_FILE": str(hosts_file)}
    return entry


def migrate(args: argparse.Namespace) -> int:
    client = args.client
    path = config_path(client)

    if client not in _JSON_CLIENTS:
        payload = _result(
            "unsupported_client_format",
            client=client,
            path=str(path),
            message=f"migrate does not yet support {client}'s config format - consolidate its "
            "yunohost-mcp-connect entries into a --hosts-file by hand",
        )
        emit(payload, args.format)
        return 1

    if not path.exists():
        payload = _result("no_action_needed", client=client, path=str(path), message="no config file found")
        emit(payload, args.format)
        return 0

    try:
        current = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BridgeConfigError(f"cannot read JSON configuration {path}: {exc}") from exc
    if not isinstance(current, dict):
        raise BridgeConfigError(f"JSON configuration {path} must contain an object")

    servers = _servers_dict(client, current)
    candidates = _find_single_host_entries(servers)

    if len(candidates) < 2:
        payload = _result(
            "no_action_needed",
            client=client,
            path=str(path),
            candidates_found=len(candidates),
            message="fewer than two split single-host yunohost-mcp-connect entries found; nothing to merge",
        )
        emit(payload, args.format)
        return 0

    used_names: set[str] = set()
    hosts: list[tuple[str, str, str]] = []
    for server_name, (remote_url, key_file, _entry) in candidates.items():
        base = _sanitize_host_name(server_name)
        host_name = base
        suffix = 2
        while host_name in used_names:
            host_name = f"{base}-{suffix}"
            suffix += 1
        used_names.add(host_name)
        hosts.append((host_name, remote_url, key_file))

    merged_name = args.name
    if merged_name in servers and merged_name not in candidates:
        raise BridgeConfigError(
            f"MCP server {merged_name!r} already exists with a different configuration in {path}; choose --name"
        )

    hosts_file = Path(args.hosts_file).expanduser() if args.hosts_file else _config_root() / "yunohost-mcp" / "hosts.toml"
    reference_entry = next(iter(candidates.values()))[2]
    merged_entry = _build_migrated_entry(client, reference_entry, hosts_file)

    if args.print_only:
        payload = _result(
            "would_migrate",
            client=client,
            path=str(path),
            hosts_file=str(hosts_file),
            hosts=[{"name": name, "remote_url": url} for name, url, _key in hosts],
            merged_name=merged_name,
            consolidated_from=sorted(candidates),
        )
        emit(payload, args.format)
        return 0

    from yunohost_mcp.hosts import HostConfig, render_hosts_toml

    hosts_file.parent.mkdir(parents=True, exist_ok=True)
    hosts_file_backup = _backup(hosts_file)
    hosts_file.write_text(
        render_hosts_toml([HostConfig(name=n, remote_url=u, key_file=Path(k)) for n, u, k in hosts])
    )

    for server_name in candidates:
        del servers[server_name]
    servers[merged_name] = merged_entry

    config_backup = _backup(path)
    path.write_text(json.dumps(current, indent=2) + "\n")

    payload = _result(
        "migrated",
        client=client,
        path=str(path),
        config_backup=str(config_backup) if config_backup else None,
        hosts_file=str(hosts_file),
        hosts_file_backup=str(hosts_file_backup) if hosts_file_backup else None,
        hosts=[{"name": name, "remote_url": url} for name, url, _key in hosts],
        merged_name=merged_name,
        consolidated_from=sorted(candidates),
        next_action="Restart or reload the MCP client to pick up the merged connection.",
    )
    emit(payload, args.format)
    return 0


def _default_hosts_file() -> Path:
    return _config_root() / "yunohost-mcp" / "hosts.toml"


def hosts_list(args: argparse.Namespace) -> int:
    from yunohost_mcp.hosts import load_hosts_file

    path = Path(args.hosts_file).expanduser() if args.hosts_file else _default_hosts_file()
    if not path.exists():
        payload = _result("no_hosts_file", path=str(path))
        emit(payload, args.format)
        return 0

    hosts = load_hosts_file(path)
    payload = _result(
        "ok",
        path=str(path),
        hosts=[{"name": h.name, "remote_url": h.remote_url, "key_file": str(h.key_file)} for h in hosts],
    )
    emit(payload, args.format)
    return 0


def hosts_add(args: argparse.Namespace) -> int:
    from yunohost_mcp.hosts import HostConfig, load_hosts_file, render_hosts_toml, validate_host_name

    if not args.server.startswith(("http://", "https://")):
        raise BridgeConfigError("--server must start with http:// or https://")

    path = Path(args.hosts_file).expanduser() if args.hosts_file else _default_hosts_file()
    existing = load_hosts_file(path, missing_ok=True)
    validate_host_name(args.name, {h.name for h in existing})

    key_file = (
        Path(args.key_file).expanduser()
        if args.key_file
        else _config_root() / "yunohost-mcp" / "hosts" / f"{args.name}.key"
    )
    key_exists = key_file.exists()

    if args.print_only:
        payload = _result(
            "would_add",
            path=str(path),
            name=args.name,
            server=args.server,
            key_file=str(key_file),
            key_would_be_generated=not key_exists,
        )
        emit(payload, args.format)
        return 0

    if key_exists:
        try:
            identity = ClientIdentity.from_key_string(key_file.read_text().strip())
        except (OSError, ValueError) as exc:
            raise BridgeConfigError(f"cannot load key file {key_file}: {exc}") from exc
        generated = False
    else:
        identity = generate_key(key_file)
        generated = True

    updated = [*existing, HostConfig(name=args.name, remote_url=args.server, key_file=key_file)]
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup(path)
    path.write_text(render_hosts_toml(updated))

    payload = _result(
        "added",
        path=str(path),
        backup=str(backup) if backup else None,
        name=args.name,
        server=args.server,
        key_file=str(key_file),
        npub=identity.npub,
        generated_key=generated,
        enrollment_required=True,
        next_action=f"Grant {identity.npub} the desired role in {args.name}'s identity.toml, then restart or "
        "reload the MCP client (or wait for the next background poll) to pick it up.",
    )
    emit(payload, args.format)
    return 0


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


def add_migrate_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "migrate",
        help="consolidate a client's split single-host yunohost-mcp-connect entries into one hosts-file entry",
    )
    parser.add_argument("--client", choices=CLIENTS, required=True)
    parser.add_argument("--name", default=DEFAULT_NAME, help="name for the merged MCP server entry")
    parser.add_argument(
        "--hosts-file", help="where to write the generated hosts-file (default: ~/.config/yunohost-mcp/hosts.toml)"
    )
    parser.add_argument("--print-only", action="store_true", help="show what would change without writing anything")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.set_defaults(handler=migrate)


def add_hosts_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("hosts", help="manage a --hosts-file's [[host]] entries")
    hosts_subparsers = parser.add_subparsers(dest="hosts_command", required=True)

    add_parser = hosts_subparsers.add_parser(
        "add", help="add a host to a hosts-file, generating a key for it if none is given"
    )
    add_parser.add_argument(
        "--hosts-file", help="path to the hosts-file (default: ~/.config/yunohost-mcp/hosts.toml)"
    )
    add_parser.add_argument("--name", required=True, help="unique name; this is the value clients pass as `host`")
    add_parser.add_argument("--server", required=True, help="remote YunoHost MCP endpoint")
    add_parser.add_argument("--key-file", help="use an existing key file instead of generating a new one")
    add_parser.add_argument("--print-only", action="store_true", help="show what would change without writing anything")
    add_parser.add_argument("--format", choices=("text", "json"), default="text")
    add_parser.set_defaults(handler=hosts_add)

    list_parser = hosts_subparsers.add_parser("list", help="list a hosts-file's entries")
    list_parser.add_argument(
        "--hosts-file", help="path to the hosts-file (default: ~/.config/yunohost-mcp/hosts.toml)"
    )
    list_parser.add_argument("--format", choices=("text", "json"), default="text")
    list_parser.set_defaults(handler=hosts_list)
