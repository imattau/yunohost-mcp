"""Client for nostr_auth's private linked-identity lookup socket."""

from __future__ import annotations

import json
import socket

from yunohost_mcp.config import Settings


class NostrAuthLookupError(RuntimeError):
    """The private nostr_auth lookup service was unavailable or invalid."""


def lookup_linked_username(pubkey: str, *, settings: Settings) -> str | None:
    path = settings.nostr_auth_lookup_socket
    if path is None:
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(settings.nostr_auth_lookup_timeout_seconds)
            sock.connect(str(path))
            sock.sendall(json.dumps({"pubkey": pubkey}, separators=(",", ":")).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise NostrAuthLookupError(f"could not reach nostr_auth lookup service: {exc}") from exc
    try:
        response = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NostrAuthLookupError(f"nostr_auth lookup returned invalid output: {exc}") from exc
    if "error" in response:
        raise NostrAuthLookupError(f"nostr_auth lookup failed: {response['error']}")
    if not isinstance(response.get("linked"), bool):
        raise NostrAuthLookupError("nostr_auth lookup returned an invalid linked flag")
    username = response.get("username")
    if username is not None and not isinstance(username, str):
        raise NostrAuthLookupError("nostr_auth lookup returned an invalid username")
    return username if response["linked"] else None
