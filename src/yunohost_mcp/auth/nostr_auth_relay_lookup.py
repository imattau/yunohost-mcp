"""Client for nostr_auth's private relay-list lookup socket (NIP-65)."""

from __future__ import annotations

import json
import socket

from yunohost_mcp.config import Settings


class NostrAuthRelayLookupError(RuntimeError):
    """The private nostr_auth relay-lookup service was unavailable or invalid."""


def lookup_linked_relays(pubkey: str, *, settings: Settings) -> list[str]:
    """The calling pubkey's own advertised relay URLs, or [] if unlinked.

    [] (not an error) also covers "linked, but has never published a
    NIP-65 relay list" - see relay_lookup_server.py in yunohost-nostr-auth
    for why that's indistinguishable from an unreachable relay, and why
    that's fine for this best-effort use.
    """
    path = settings.nostr_auth_relay_lookup_socket
    if path is None:
        return []
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(settings.nostr_auth_relay_lookup_timeout_seconds)
            sock.connect(str(path))
            sock.sendall(json.dumps({"pubkey": pubkey}, separators=(",", ":")).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise NostrAuthRelayLookupError(f"could not reach nostr_auth relay-lookup service: {exc}") from exc
    try:
        response = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NostrAuthRelayLookupError(f"nostr_auth relay-lookup returned invalid output: {exc}") from exc
    if "error" in response:
        raise NostrAuthRelayLookupError(f"nostr_auth relay-lookup failed: {response['error']}")
    if not isinstance(response.get("linked"), bool) or not isinstance(response.get("relays"), list):
        raise NostrAuthRelayLookupError("nostr_auth relay-lookup returned an invalid response")
    if not response["linked"]:
        return []
    try:
        urls = [entry["url"] for entry in response["relays"]]
    except (KeyError, TypeError) as exc:
        raise NostrAuthRelayLookupError("nostr_auth relay-lookup returned an invalid relay entry") from exc
    if not all(isinstance(url, str) for url in urls):
        raise NostrAuthRelayLookupError("nostr_auth relay-lookup returned a non-string relay URL")
    return urls
