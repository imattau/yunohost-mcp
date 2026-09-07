"""Parsing for the multi-host bridge's `--hosts-file`/`$YUNOHOST_MCP_CLIENT_HOSTS_FILE`
config: a small TOML file listing every YunoHost server one `yunohost-mcp-connect`
process should bridge at once (see bridge.py's multi-host mode).

    [[host]]
    name = "lostcause"
    remote_url = "https://mcp.lostcause.nohost.me/mcp"
    key_file = "/home/lostcause/.config/yunohost-mcp/claude-code.key"

    [[host]]
    name = "3nostr"
    remote_url = "https://mcp.3nostr.com/mcp"
    key_file = "/home/lostcause/.config/yunohost-mcp/claude-code-3nostr.key"
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from yunohost_mcp.bridge import BridgeConfigError


@dataclass(frozen=True)
class HostConfig:
    name: str
    remote_url: str
    key_file: Path


def validate_host_name(name: str, existing_names: set[str] = frozenset()) -> None:
    """Shared rule for every host name, whether it comes from parsing a
    hosts-file or from `hosts add`: non-empty, unique, and dot-free (host
    names are spliced into bridge.py's multi-host resource URIs, which
    forbids '.')."""
    if not name:
        raise BridgeConfigError("host name must not be empty")
    if "." in name:
        raise BridgeConfigError(f"host name {name!r} must not contain '.' (host names are spliced into resource URIs)")
    if name in existing_names:
        raise BridgeConfigError(f"duplicate host name {name!r}")


def render_hosts_toml(hosts: list[HostConfig]) -> str:
    blocks = [
        "[[host]]\n"
        f"name = {json.dumps(host.name)}\n"
        f"remote_url = {json.dumps(host.remote_url)}\n"
        f"key_file = {json.dumps(str(host.key_file))}\n"
        for host in hosts
    ]
    return "\n".join(blocks) + "\n"


def load_hosts_file(path: Path, *, missing_ok: bool = False) -> list[HostConfig]:
    path = Path(path)
    try:
        text = path.read_text()
    except OSError as exc:
        if missing_ok and not path.exists():
            return []
        raise BridgeConfigError(f"could not read hosts file {path}: {exc}") from exc

    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise BridgeConfigError(f"invalid TOML in hosts file {path}: {exc}") from exc

    entries = raw.get("host")
    if not entries:
        raise BridgeConfigError(f"hosts file {path} has no [[host]] entries")

    hosts: list[HostConfig] = []
    seen_names: set[str] = set()
    for i, entry in enumerate(entries):
        name = entry.get("name")
        remote_url = entry.get("remote_url")
        key_file = entry.get("key_file")
        if not name:
            raise BridgeConfigError(f"hosts file {path}: entry {i} is missing 'name'")
        validate_host_name(name, seen_names)
        if not remote_url:
            raise BridgeConfigError(f"hosts file {path}: host {name!r} is missing 'remote_url'")
        if not key_file:
            raise BridgeConfigError(f"hosts file {path}: host {name!r} is missing 'key_file'")
        seen_names.add(name)
        hosts.append(HostConfig(name=name, remote_url=remote_url, key_file=Path(key_file).expanduser()))

    return hosts
