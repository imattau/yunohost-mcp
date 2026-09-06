from __future__ import annotations

import json
import socketserver
import threading

import pytest

from yunohost_mcp.auth.nostr_auth_relay_lookup import NostrAuthRelayLookupError, lookup_linked_relays
from yunohost_mcp.config import Settings

PUBKEY = "a" * 64


class _Handler(socketserver.BaseRequestHandler):
    server: "_FakeServer"

    def handle(self) -> None:
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = self.request.recv(4096)
            if not chunk:
                break
            raw += chunk
        self.request.sendall(json.dumps(self.server.response).encode() + b"\n")


class _FakeServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path, response: dict) -> None:
        self.response = response
        super().__init__(str(socket_path), _Handler)


def _start(tmp_path, response: dict):
    path = tmp_path / "relays.sock"
    server = _FakeServer(path, response)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return path, server, thread


def _settings(socket_path) -> Settings:
    return Settings(fake_yunohost=False, nostr_auth_relay_lookup_socket=socket_path)


def test_returns_empty_list_when_socket_is_not_configured():
    assert lookup_linked_relays(PUBKEY, settings=Settings(fake_yunohost=False)) == []


def test_unreachable_socket_raises():
    with pytest.raises(NostrAuthRelayLookupError, match="could not reach"):
        lookup_linked_relays(PUBKEY, settings=_settings("/does/not/exist.sock"))


def test_unlinked_pubkey_returns_empty_list(tmp_path):
    path, server, thread = _start(tmp_path, {"linked": False, "relays": [], "fetched_at": None})
    try:
        assert lookup_linked_relays(PUBKEY, settings=_settings(path)) == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_linked_pubkey_returns_relay_urls(tmp_path):
    response = {
        "linked": True,
        "relays": [
            {"url": "wss://relay.example", "read": True, "write": True},
            {"url": "wss://write-only.example", "read": False, "write": True},
        ],
        "fetched_at": 1234,
    }
    path, server, thread = _start(tmp_path, response)
    try:
        assert lookup_linked_relays(PUBKEY, settings=_settings(path)) == ["wss://relay.example", "wss://write-only.example"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_error_response_raises(tmp_path):
    path, server, thread = _start(tmp_path, {"error": "forbidden"})
    try:
        with pytest.raises(NostrAuthRelayLookupError, match="forbidden"):
            lookup_linked_relays(PUBKEY, settings=_settings(path))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_malformed_response_raises(tmp_path):
    path, server, thread = _start(tmp_path, {"linked": "yes", "relays": []})
    try:
        with pytest.raises(NostrAuthRelayLookupError, match="invalid response"):
            lookup_linked_relays(PUBKEY, settings=_settings(path))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
