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


def test_live_store_picks_up_a_new_revocation_without_reconstruction(tmp_path: Path):
    path = tmp_path / "revoked_delegations.toml"
    store = RevocationStore.live(path)

    assert not store.is_revoked("abc123")
    assert len(store) == 0

    # An admin revokes a delegation by editing the file - takes effect on
    # the very next check, no restart, no new store instance.
    path.write_text('revoked = ["abc123"]\n')
    assert store.is_revoked("abc123")
    assert not store.is_revoked("other")
    assert len(store) == 1


def test_live_store_treats_transient_parse_error_as_fully_revoked(tmp_path: Path):
    path = tmp_path / "revoked_delegations.toml"
    path.write_text('revoked = ["abc123"]\n')
    store = RevocationStore.live(path)
    assert store.is_revoked("abc123")
    assert not store.is_revoked("other")

    # A mid-edit typo must fail safe: everything is treated as revoked
    # (nothing trusted), the opposite fail-safe direction from
    # IdentityStore's "deny by default", but the same principle - a broken
    # config file must never silently behave like an empty/permissive one.
    path.write_text("not [valid toml")
    assert store.is_revoked("abc123")
    assert store.is_revoked("other")
    assert len(store) == 0

    path.write_text('revoked = ["abc123"]\n')
    assert store.is_revoked("abc123")
    assert not store.is_revoked("other")


def test_static_load_is_unaffected_by_later_file_changes(tmp_path: Path):
    path = tmp_path / "revoked_delegations.toml"
    path.write_text('revoked = ["abc123"]\n')
    store = RevocationStore.load(path)
    path.write_text("")
    assert store.is_revoked("abc123")
