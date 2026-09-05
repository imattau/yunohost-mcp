from __future__ import annotations

import argparse
import json
import os
import stat

import pytest

from yunohost_mcp import onboarding


def _setup_args(tmp_path, client="claude-desktop", output_format="json", print_only=False):
    return argparse.Namespace(
        server="https://example.test/mcp",
        client=client,
        key_file=str(tmp_path / f"{client}.key"),
        name="yunohost-mcp",
        print_only=print_only,
        non_interactive=True,
        format=output_format,
    )


def test_setup_writes_json_config_and_secure_key(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    assert onboarding.setup(_setup_args(tmp_path)) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "awaiting_enrollment"
    assert result["npub"].startswith("npub1")
    assert result["configuration"]["written"] is True
    assert stat.S_IMODE(os.stat(result["key_file"]).st_mode) == 0o600
    saved = json.loads(config.read_text())
    assert saved["mcpServers"]["yunohost-mcp"]["command"] == "uvx"
    assert saved["mcpServers"]["yunohost-mcp"]["args"] == ["--from", "yunohost-mcp-connect", "yunohost-mcp-connect"]


def test_setup_preserves_unrelated_json_servers(tmp_path, monkeypatch):
    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}, "custom": True}))
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    onboarding.setup(_setup_args(tmp_path, output_format="text"))

    saved = json.loads(config.read_text())
    assert saved["custom"] is True
    assert saved["mcpServers"]["other"] == {"command": "other"}
    assert list(tmp_path.glob("claude.json.yunohost-mcp-backup*"))


def test_setup_refuses_conflicting_json_server(tmp_path, monkeypatch):
    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"mcpServers": {"yunohost-mcp": {"command": "unsafe"}}}))
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    with pytest.raises(Exception, match="already exists"):
        onboarding.setup(_setup_args(tmp_path))


def test_setup_print_only_does_not_write_config(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    onboarding.setup(_setup_args(tmp_path, print_only=True))

    result = json.loads(capsys.readouterr().out)
    assert result["configuration"]["written"] is False
    assert not config.exists()
    assert result["key_file"]


def test_setup_non_interactive_requires_server_and_client(tmp_path):
    args = _setup_args(tmp_path)
    args.server = None

    with pytest.raises(Exception, match="requires both --server and --client"):
        onboarding.setup(args)


def test_setup_interactive_prompts_for_missing_values(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    answers = iter(["1", "https://example.test/mcp"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    args = _setup_args(tmp_path, output_format="json")
    args.client = None
    args.server = None
    args.non_interactive = False

    assert onboarding.setup(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["client"] == "codex"
    assert result["server"] == "https://example.test/mcp"


def test_codex_config_is_uvx_based_and_idempotent(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    args = _setup_args(tmp_path, client="codex", output_format="text")

    onboarding.setup(args)
    first = config.read_text()
    onboarding.setup(args)
    assert config.read_text() == first


def test_codex_config_refuses_stale_endpoint_or_key(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    onboarding.setup(_setup_args(tmp_path, client="codex", output_format="text"))
    args = _setup_args(tmp_path, client="codex", output_format="text")
    args.server = "https://different.example/mcp"

    with pytest.raises(Exception, match="different configuration"):
        onboarding.setup(args)


def test_doctor_reports_missing_key(tmp_path, capsys):
    args = argparse.Namespace(server="https://example.test/mcp", key_file=str(tmp_path / "missing.key"), format="json")

    assert onboarding.doctor(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "local_missing_key"


def test_doctor_reports_healthy_connection(tmp_path, monkeypatch, capsys):
    key = tmp_path / "key"
    onboarding.generate_key(key)
    async def healthy(server, key_file):
        return {"status": "healthy", "tool_count": 2, "npub": "npub1test"}

    monkeypatch.setattr(onboarding, "_doctor_remote", healthy)
    args = argparse.Namespace(server="https://example.test/mcp", key_file=str(key), format="json")

    assert onboarding.doctor(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "healthy"
    assert result["server"] == "https://example.test/mcp"


def test_hermes_config_inserts_inside_existing_section(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("other:\n  value: true\nmcp_servers:\n  existing:\n    command: existing\nprofiles:\n  default: true\n")
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    onboarding.setup(_setup_args(tmp_path, client="hermes", output_format="text"))

    saved = config.read_text()
    assert saved.index("  yunohost-mcp:") < saved.index("profiles:")
