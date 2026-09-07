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


def test_gemini_config_uses_mcp_servers(tmp_path, monkeypatch):
    config = tmp_path / "settings.json"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    onboarding.setup(_setup_args(tmp_path, client="gemini", output_format="text"))

    saved = json.loads(config.read_text())
    assert saved["mcpServers"]["yunohost-mcp"]["command"] == "uvx"
    assert saved["mcpServers"]["yunohost-mcp"]["env"]["YUNOHOST_MCP_CLIENT_KEY_FILE"].endswith("gemini.key")


def test_opencode_config_uses_local_server_shape(tmp_path, monkeypatch):
    config = tmp_path / "opencode.json"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    onboarding.setup(_setup_args(tmp_path, client="opencode", output_format="text"))

    saved = json.loads(config.read_text())
    entry = saved["mcp"]["servers"]["yunohost-mcp"]
    assert entry["type"] == "local"
    assert entry["command"][:2] == ["uvx", "--from"]


def test_openclaw_config_uses_mcp_server_shape(tmp_path, monkeypatch):
    config = tmp_path / "openclaw.json"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    onboarding.setup(_setup_args(tmp_path, client="openclaw", output_format="text"))

    saved = json.loads(config.read_text())
    entry = saved["mcp"]["servers"]["yunohost-mcp"]
    assert entry["command"] == "uvx"
    assert entry["args"][-1] == "yunohost-mcp-connect"


def _migrate_args(client="claude-code", name="yunohost-mcp", hosts_file=None, print_only=False, output_format="json"):
    return argparse.Namespace(
        client=client, name=name, hosts_file=hosts_file, print_only=print_only, format=output_format
    )


def _single_host_entry(remote_url: str, key_file: str) -> dict:
    return {
        "command": "/home/user/.local/share/yunohost-mcp-client/venv/bin/yunohost-mcp-connect",
        "args": [],
        "env": {"YUNOHOST_MCP_CLIENT_REMOTE_URL": remote_url, "YUNOHOST_MCP_CLIENT_KEY_FILE": key_file},
    }


def test_migrate_merges_two_split_entries_into_a_hosts_file(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "yunohost-mcp": _single_host_entry("https://a.example/mcp", "/keys/a.key"),
                    "yunohost-mcp-3nostr": _single_host_entry("https://b.example/mcp", "/keys/b.key"),
                }
            }
        )
    )
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    hosts_file = tmp_path / "hosts.toml"

    code = onboarding.migrate(_migrate_args(hosts_file=str(hosts_file)))

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "migrated"
    assert sorted(result["consolidated_from"]) == ["yunohost-mcp", "yunohost-mcp-3nostr"]

    saved = json.loads(config.read_text())
    servers = saved["mcpServers"]
    assert set(servers) == {"yunohost-mcp"}
    merged = servers["yunohost-mcp"]
    assert merged["command"].endswith("yunohost-mcp-connect")
    assert merged["env"] == {"YUNOHOST_MCP_CLIENT_HOSTS_FILE": str(hosts_file)}

    hosts_toml = hosts_file.read_text()
    assert 'remote_url = "https://a.example/mcp"' in hosts_toml
    assert 'remote_url = "https://b.example/mcp"' in hosts_toml
    assert hosts_toml.count("[[host]]") == 2


def test_migrate_reports_no_action_with_fewer_than_two_candidates(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"mcpServers": {"yunohost-mcp": _single_host_entry("https://a.example/mcp", "/keys/a.key")}}))
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    code = onboarding.migrate(_migrate_args())

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "no_action_needed"
    assert result["candidates_found"] == 1
    assert json.loads(config.read_text())["mcpServers"] == {
        "yunohost-mcp": _single_host_entry("https://a.example/mcp", "/keys/a.key")
    }


def test_migrate_ignores_unrelated_and_already_migrated_entries(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "yunohost-mcp": _single_host_entry("https://a.example/mcp", "/keys/a.key"),
                    "other-tool": {"command": "some-other-mcp-server"},
                    "already-merged": {
                        "command": "yunohost-mcp-connect",
                        "env": {"YUNOHOST_MCP_CLIENT_HOSTS_FILE": "/keys/hosts.toml"},
                    },
                }
            }
        )
    )
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    code = onboarding.migrate(_migrate_args())

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "no_action_needed"
    assert result["candidates_found"] == 1


def test_migrate_print_only_does_not_write_anything(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    original = json.dumps(
        {
            "mcpServers": {
                "yunohost-mcp": _single_host_entry("https://a.example/mcp", "/keys/a.key"),
                "yunohost-mcp-3nostr": _single_host_entry("https://b.example/mcp", "/keys/b.key"),
            }
        }
    )
    config.write_text(original)
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    hosts_file = tmp_path / "hosts.toml"

    code = onboarding.migrate(_migrate_args(hosts_file=str(hosts_file), print_only=True))

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "would_migrate"
    assert config.read_text() == original
    assert not hosts_file.exists()


def test_migrate_sanitizes_dotted_server_names_for_host_names(tmp_path, monkeypatch, capsys):
    config = tmp_path / "claude.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "yunohost.lostcause": _single_host_entry("https://a.example/mcp", "/keys/a.key"),
                    "yunohost.3nostr": _single_host_entry("https://b.example/mcp", "/keys/b.key"),
                }
            }
        )
    )
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    hosts_file = tmp_path / "hosts.toml"

    code = onboarding.migrate(_migrate_args(hosts_file=str(hosts_file)))

    assert code == 0
    hosts_toml = hosts_file.read_text()
    assert "." not in "".join(
        line.split("=", 1)[1].strip().strip('"') for line in hosts_toml.splitlines() if line.startswith("name")
    )


def test_migrate_unsupported_client_format(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.toml"
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)

    code = onboarding.migrate(_migrate_args(client="codex"))

    assert code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "unsupported_client_format"


def test_migrate_opencode_shape(tmp_path, monkeypatch, capsys):
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "servers": {
                        "yunohost-mcp": {
                            "type": "local",
                            "command": ["uvx", "--from", "yunohost-mcp-connect", "yunohost-mcp-connect"],
                            "environment": {
                                "YUNOHOST_MCP_CLIENT_REMOTE_URL": "https://a.example/mcp",
                                "YUNOHOST_MCP_CLIENT_KEY_FILE": "/keys/a.key",
                            },
                        },
                        "yunohost-mcp-3nostr": {
                            "type": "local",
                            "command": ["uvx", "--from", "yunohost-mcp-connect", "yunohost-mcp-connect"],
                            "environment": {
                                "YUNOHOST_MCP_CLIENT_REMOTE_URL": "https://b.example/mcp",
                                "YUNOHOST_MCP_CLIENT_KEY_FILE": "/keys/b.key",
                            },
                        },
                    }
                }
            }
        )
    )
    monkeypatch.setattr(onboarding, "config_path", lambda client: config)
    hosts_file = tmp_path / "hosts.toml"

    code = onboarding.migrate(_migrate_args(client="opencode", hosts_file=str(hosts_file)))

    assert code == 0
    saved = json.loads(config.read_text())
    servers = saved["mcp"]["servers"]
    assert set(servers) == {"yunohost-mcp"}
    merged = servers["yunohost-mcp"]
    assert merged["command"] == ["uvx", "--from", "yunohost-mcp-connect", "yunohost-mcp-connect"]
    assert merged["environment"] == {"YUNOHOST_MCP_CLIENT_HOSTS_FILE": str(hosts_file)}


def _hosts_add_args(hosts_file, name="a", server="https://a.example/mcp", key_file=None, print_only=False, output_format="json"):
    return argparse.Namespace(
        hosts_file=str(hosts_file), name=name, server=server, key_file=key_file, print_only=print_only, format=output_format
    )


def test_hosts_add_generates_a_key_and_creates_the_hosts_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(onboarding, "_config_root", lambda: tmp_path / "config-root")
    hosts_file = tmp_path / "hosts.toml"

    code = onboarding.hosts_add(_hosts_add_args(hosts_file))

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "added"
    assert result["generated_key"] is True
    assert result["npub"].startswith("npub1")

    from yunohost_mcp.hosts import load_hosts_file

    hosts = load_hosts_file(hosts_file)
    assert len(hosts) == 1
    assert hosts[0].name == "a"
    assert hosts[0].remote_url == "https://a.example/mcp"
    assert hosts[0].key_file.exists()
    assert hosts[0].key_file.is_relative_to(tmp_path)
    assert stat.S_IMODE(hosts[0].key_file.stat().st_mode) == 0o600


def test_hosts_add_appends_to_an_existing_hosts_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(onboarding, "_config_root", lambda: tmp_path / "config-root")
    hosts_file = tmp_path / "hosts.toml"
    onboarding.hosts_add(_hosts_add_args(hosts_file, name="a", server="https://a.example/mcp"))
    capsys.readouterr()

    code = onboarding.hosts_add(_hosts_add_args(hosts_file, name="b", server="https://b.example/mcp"))

    assert code == 0
    from yunohost_mcp.hosts import load_hosts_file

    hosts = load_hosts_file(hosts_file)
    assert [h.name for h in hosts] == ["a", "b"]


def test_hosts_add_reuses_an_existing_key_file(tmp_path, capsys):
    hosts_file = tmp_path / "hosts.toml"
    key_file = tmp_path / "existing.key"
    identity = onboarding.generate_key(key_file)
    capsys.readouterr()

    code = onboarding.hosts_add(_hosts_add_args(hosts_file, key_file=str(key_file)))

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["generated_key"] is False
    assert result["npub"] == identity.npub


def test_hosts_add_rejects_duplicate_and_dotted_names(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(onboarding, "_config_root", lambda: tmp_path / "config-root")
    hosts_file = tmp_path / "hosts.toml"
    onboarding.hosts_add(_hosts_add_args(hosts_file, name="a"))
    capsys.readouterr()

    with pytest.raises(Exception, match="duplicate host name"):
        onboarding.hosts_add(_hosts_add_args(hosts_file, name="a", server="https://other.example/mcp"))

    with pytest.raises(Exception, match="must not contain"):
        onboarding.hosts_add(_hosts_add_args(hosts_file, name="a.b", server="https://other.example/mcp"))


def test_hosts_add_rejects_bad_server_url(tmp_path, monkeypatch):
    monkeypatch.setattr(onboarding, "_config_root", lambda: tmp_path / "config-root")
    hosts_file = tmp_path / "hosts.toml"
    with pytest.raises(Exception, match="http"):
        onboarding.hosts_add(_hosts_add_args(hosts_file, server="not-a-url"))


def test_hosts_add_print_only_does_not_write_or_generate_a_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(onboarding, "_config_root", lambda: tmp_path / "config-root")
    hosts_file = tmp_path / "hosts.toml"

    code = onboarding.hosts_add(_hosts_add_args(hosts_file, print_only=True))

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "would_add"
    assert not hosts_file.exists()
    assert result["key_would_be_generated"] is True
    assert not (tmp_path / "config-root").exists()


def test_hosts_list_reports_no_hosts_file_when_missing(tmp_path, capsys):
    args = argparse.Namespace(hosts_file=str(tmp_path / "missing.toml"), format="json")

    code = onboarding.hosts_list(args)

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "no_hosts_file"


def test_hosts_list_reports_existing_entries(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(onboarding, "_config_root", lambda: tmp_path / "config-root")
    hosts_file = tmp_path / "hosts.toml"
    onboarding.hosts_add(_hosts_add_args(hosts_file, name="a", server="https://a.example/mcp"))
    capsys.readouterr()
    onboarding.hosts_add(_hosts_add_args(hosts_file, name="b", server="https://b.example/mcp"))
    capsys.readouterr()

    args = argparse.Namespace(hosts_file=str(hosts_file), format="json")
    code = onboarding.hosts_list(args)

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert [h["name"] for h in result["hosts"]] == ["a", "b"]
