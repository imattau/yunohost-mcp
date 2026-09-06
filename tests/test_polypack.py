from __future__ import annotations

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.polypack import PolypackClient, PolypackUnavailableError, _loopback_url
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostAdapter


def test_loopback_url_accepts_local_mcp_endpoint():
    assert _loopback_url("http://127.0.0.1:8766/mcp/") == "http://127.0.0.1:8766/mcp/"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/mcp/",
        "http://user:password@127.0.0.1:8766/mcp/",
        "http://127.0.0.1:8766/mcp/?token=secret",
        "http://127.0.0.1:8766",
    ],
)
def test_loopback_url_rejects_non_local_or_ambiguous_endpoints(url: str):
    with pytest.raises(ToolInputError):
        _loopback_url(url)


def test_unconfigured_polypack_is_reported_as_optional_service_failure(tmp_path):
    client = PolypackClient(Settings(fake_yunohost=True, config_dir=tmp_path))
    with pytest.raises(PolypackUnavailableError, match="YUNOHOST_MCP_POLYPACK_URL"):
        client.call_tool("memory_list_contexts", {})


def test_adapter_forwards_typed_memory_store_and_server_provenance(monkeypatch: pytest.MonkeyPatch, tmp_path):
    settings = Settings(
        fake_yunohost=True,
        config_dir=tmp_path,
        polypack_url="http://127.0.0.1:8766/mcp/",
    )
    adapter = YunohostAdapter(settings)
    seen: list[tuple[str, dict]] = []

    def fake_call(self, tool: str, arguments: dict):
        seen.append((tool, arguments))
        return {"stored": True}

    monkeypatch.setattr(PolypackClient, "call_tool", fake_call)

    result = adapter.memory_store(
        "hello",
        context="project",
        metadata={"kind": "note"},
        provenance={"_yunohost_source": "yunohost-mcp", "_yunohost_caller_pubkey": "abc"},
    )

    assert result == {"stored": True}
    assert seen == [
        (
            "memory_store",
            {
                "content": "hello",
                "context": "project",
                "memory_class": "semantic",
                "metadata": {"kind": "note"},
                "provenance": {"_yunohost_source": "yunohost-mcp", "_yunohost_caller_pubkey": "abc"},
            },
        )
    ]


def test_adapter_rejects_user_supplied_yunohost_metadata(monkeypatch: pytest.MonkeyPatch, tmp_path):
    adapter = YunohostAdapter(
        Settings(fake_yunohost=True, config_dir=tmp_path, polypack_url="http://127.0.0.1:8766/mcp/")
    )
    monkeypatch.setattr(PolypackClient, "call_tool", lambda *args: {"stored": True})

    with pytest.raises(ToolInputError, match="reserved"):
        adapter.memory_store(
            "hello",
            metadata={"_yunohost_caller_pubkey": "forged"},
            provenance={"_yunohost_caller_pubkey": "real"},
        )


def test_adapter_forwards_feedback_with_authenticated_agent_id(monkeypatch: pytest.MonkeyPatch, tmp_path):
    adapter = YunohostAdapter(
        Settings(fake_yunohost=True, config_dir=tmp_path, polypack_url="http://127.0.0.1:8766/mcp/")
    )
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        PolypackClient,
        "call_tool",
        lambda self, tool, arguments: seen.append((tool, arguments)) or {"updated": True},
    )

    assert adapter.memory_feedback("memory-1", useful=True, agent_id="agent-1") == {"updated": True}
    assert seen == [("memory_feedback", {"memory_id": "memory-1", "useful": True, "agent_id": "agent-1"})]
