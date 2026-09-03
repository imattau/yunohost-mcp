from __future__ import annotations

from pathlib import Path

import pytest

from yunohost_mcp.auth.revocation import RevocationConfigError, RevocationStore


def test_missing_file_yields_empty_store(tmp_path: Path):
    store = RevocationStore.load(tmp_path / "does-not-exist.toml")
    assert len(store) == 0
    assert not store.is_revoked("anything")


def test_loads_revoked_ids(tmp_path: Path):
    path = tmp_path / "revoked_delegations.toml"
    path.write_text('revoked = ["abc123", "def456"]\n')
    store = RevocationStore.load(path)
    assert store.is_revoked("abc123")
    assert store.is_revoked("def456")
    assert not store.is_revoked("other")
    assert len(store) == 2


def test_malformed_toml_raises(tmp_path: Path):
    path = tmp_path / "revoked_delegations.toml"
    path.write_text("not [valid toml")
    with pytest.raises(RevocationConfigError):
        RevocationStore.load(path)


def test_non_list_revoked_field_raises(tmp_path: Path):
    path = tmp_path / "revoked_delegations.toml"
    path.write_text('revoked = "not-a-list"\n')
    with pytest.raises(RevocationConfigError):
        RevocationStore.load(path)
