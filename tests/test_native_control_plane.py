from __future__ import annotations

from yunohost_mcp import server


class FakeNativeAdapter:
    actor_pubkey = None

    def call_tool(self, tool, arguments=None, *, actor_pubkey=None):
        self.actor_pubkey = actor_pubkey
        return {
            "content": [{"type": "text", "text": "operation submitted"}],
            "isError": False,
            "_nostr": {"request_id": "a" * 64, "kind": 2200},
        }


def test_native_control_plane_tool_delegates_to_signed_adapter(monkeypatch):
    monkeypatch.setattr(server.settings, "native_control_plane_enabled", True)
    monkeypatch.setattr(server, "_get_native_control_plane_adapter", lambda: FakeNativeAdapter())

    result = server.native_control_plane_call("system.version", {"verbose": False})

    assert result["_nostr"]["request_id"] == "a" * 64


def test_native_control_plane_passes_authenticated_nostr_actor(monkeypatch):
    monkeypatch.setattr(server.settings, "native_control_plane_enabled", True)
    adapter = FakeNativeAdapter()
    monkeypatch.setattr(server, "_get_native_control_plane_adapter", lambda: adapter)
    monkeypatch.setattr(server, "get_current_request", lambda: type("Request", (), {"pubkey": "b" * 64})())

    server.native_control_plane_call("system.version")

    assert adapter.actor_pubkey == "b" * 64
