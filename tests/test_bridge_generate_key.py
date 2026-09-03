"""Unit tests for bridge.py's --generate-key: writing a fresh client key
without needing a live remote server.

Exists because the path of least resistance without a built-in generator -
copying a key file that already works for one client into another's
config - produces no error, no warning, and silently gives the second
client the first one's exact permissions (whichever key signs a request
is that request's entire identity on the server). See generate_key()'s
own docstring.
"""

from __future__ import annotations

import stat
import sys

import pytest

from yunohost_mcp.auth.signing import ClientIdentity
from yunohost_mcp.bridge import BridgeConfigError, generate_key, main


def test_generate_key_writes_a_valid_key(tmp_path):
    path = tmp_path / "codex.key"
    identity = generate_key(path)

    content = path.read_text().strip()
    assert len(content) == 64
    int(content, 16)  # a valid 64-char hex string

    # The file's own content, reparsed independently, must match the
    # identity generate_key() already returned - not a different key.
    reparsed = ClientIdentity.from_key_string(content)
    assert reparsed.npub == identity.npub
    assert reparsed.pubkey_hex == identity.pubkey_hex


def test_generate_key_sets_owner_only_permissions(tmp_path):
    path = tmp_path / "codex.key"
    generate_key(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_generate_key_creates_missing_parent_directories(tmp_path):
    path = tmp_path / "nested" / "dir" / "codex.key"
    generate_key(path)
    assert path.exists()


def test_generate_key_refuses_to_overwrite_an_existing_file(tmp_path):
    path = tmp_path / "codex.key"
    path.write_text("existing-content")

    with pytest.raises(BridgeConfigError, match="refusing to overwrite"):
        generate_key(path)

    # The original file must be untouched, not partially overwritten.
    assert path.read_text() == "existing-content"


def test_generate_key_produces_distinct_keys_across_calls(tmp_path):
    identity_a = generate_key(tmp_path / "a.key")
    identity_b = generate_key(tmp_path / "b.key")
    assert identity_a.npub != identity_b.npub


def test_cli_generate_key_prints_npub_and_exits_without_a_remote_url(tmp_path, monkeypatch, capsys):
    # --generate-key must work standalone - no --remote-url needed, and it
    # must not attempt to connect anywhere.
    path = tmp_path / "codex.key"
    monkeypatch.setattr(sys, "argv", ["yunohost-mcp-connect", "--generate-key", str(path)])

    main()

    assert path.exists()
    captured = capsys.readouterr()
    identity = ClientIdentity.from_key_string(path.read_text())
    assert identity.npub in captured.err
    assert "identity.toml" in captured.err


def test_cli_generate_key_refusing_overwrite_surfaces_as_bridge_config_error(tmp_path, monkeypatch):
    path = tmp_path / "codex.key"
    path.write_text("existing-content")
    monkeypatch.setattr(sys, "argv", ["yunohost-mcp-connect", "--generate-key", str(path)])

    with pytest.raises(BridgeConfigError, match="refusing to overwrite"):
        main()
