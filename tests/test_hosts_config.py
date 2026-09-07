"""Unit tests for hosts.py's --hosts-file TOML parsing/validation."""

from __future__ import annotations

import pytest

from yunohost_mcp.bridge import BridgeConfigError
from yunohost_mcp.hosts import HostConfig, load_hosts_file, render_hosts_toml, validate_host_name


def _write(tmp_path, text: str):
    path = tmp_path / "hosts.toml"
    path.write_text(text)
    return path


def test_load_hosts_file_parses_valid_entries(tmp_path):
    path = _write(
        tmp_path,
        """
        [[host]]
        name = "a"
        remote_url = "https://a.example/mcp"
        key_file = "~/keys/a.key"

        [[host]]
        name = "b"
        remote_url = "https://b.example/mcp"
        key_file = "/keys/b.key"
        """,
    )
    hosts = load_hosts_file(path)
    assert hosts[0].name == "a"
    assert hosts[0].remote_url == "https://a.example/mcp"
    assert hosts[0].key_file.name == "a.key"
    assert isinstance(hosts[0], HostConfig)
    assert hosts[1].name == "b"


def test_load_hosts_file_requires_at_least_one_host(tmp_path):
    path = _write(tmp_path, "")
    with pytest.raises(BridgeConfigError, match="no \\[\\[host\\]\\] entries"):
        load_hosts_file(path)


def test_load_hosts_file_rejects_duplicate_names(tmp_path):
    path = _write(
        tmp_path,
        """
        [[host]]
        name = "a"
        remote_url = "https://a.example/mcp"
        key_file = "/keys/a.key"

        [[host]]
        name = "a"
        remote_url = "https://a2.example/mcp"
        key_file = "/keys/a2.key"
        """,
    )
    with pytest.raises(BridgeConfigError, match="duplicate host name"):
        load_hosts_file(path)


def test_load_hosts_file_rejects_dotted_names(tmp_path):
    path = _write(
        tmp_path,
        """
        [[host]]
        name = "a.b"
        remote_url = "https://a.example/mcp"
        key_file = "/keys/a.key"
        """,
    )
    with pytest.raises(BridgeConfigError, match="must not contain"):
        load_hosts_file(path)


def test_load_hosts_file_requires_remote_url(tmp_path):
    path = _write(
        tmp_path,
        """
        [[host]]
        name = "a"
        key_file = "/keys/a.key"
        """,
    )
    with pytest.raises(BridgeConfigError, match="missing 'remote_url'"):
        load_hosts_file(path)


def test_load_hosts_file_requires_key_file(tmp_path):
    path = _write(
        tmp_path,
        """
        [[host]]
        name = "a"
        remote_url = "https://a.example/mcp"
        """,
    )
    with pytest.raises(BridgeConfigError, match="missing 'key_file'"):
        load_hosts_file(path)


def test_load_hosts_file_rejects_invalid_toml(tmp_path):
    path = _write(tmp_path, "not valid toml [[[")
    with pytest.raises(BridgeConfigError, match="invalid TOML"):
        load_hosts_file(path)


def test_load_hosts_file_rejects_missing_file(tmp_path):
    with pytest.raises(BridgeConfigError, match="could not read"):
        load_hosts_file(tmp_path / "missing.toml")


def test_load_hosts_file_missing_ok_returns_empty_list(tmp_path):
    assert load_hosts_file(tmp_path / "missing.toml", missing_ok=True) == []


def test_validate_host_name_rejects_empty_dotted_and_duplicate_names():
    validate_host_name("ok")
    with pytest.raises(BridgeConfigError, match="must not be empty"):
        validate_host_name("")
    with pytest.raises(BridgeConfigError, match="must not contain"):
        validate_host_name("a.b")
    with pytest.raises(BridgeConfigError, match="duplicate host name"):
        validate_host_name("a", {"a", "b"})


def test_render_hosts_toml_round_trips_through_load_hosts_file(tmp_path):
    hosts = [
        HostConfig(name="a", remote_url="https://a.example/mcp", key_file=tmp_path / "a.key"),
        HostConfig(name="b", remote_url="https://b.example/mcp", key_file=tmp_path / "b.key"),
    ]
    path = tmp_path / "hosts.toml"
    path.write_text(render_hosts_toml(hosts))

    loaded = load_hosts_file(path)
    assert [h.name for h in loaded] == ["a", "b"]
    assert [h.remote_url for h in loaded] == ["https://a.example/mcp", "https://b.example/mcp"]
