from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from yunohost_mcp.auth.identity import IdentityConfigError, IdentityStore
from yunohost_mcp.auth.npub import hex_to_npub
from yunohost_mcp.policy.scopes import Scope

HEX_PUBKEY = "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"


def test_missing_file_yields_empty_store(tmp_path: Path):
    store = IdentityStore.load(tmp_path / "does-not-exist.toml")
    assert len(store) == 0
    assert store.lookup(HEX_PUBKEY) is None


def test_loads_npub_keyed_entry(tmp_path: Path):
    npub = hex_to_npub(HEX_PUBKEY)
    toml_path = tmp_path / "identity.toml"
    toml_path.write_text(
        f"""
[identity."{npub}"]
name = "Codex development agent"
roles = ["package-developer"]
expires = "2099-12-31T00:00:00+00:00"
"""
    )
    store = IdentityStore.load(toml_path)
    record = store.lookup(HEX_PUBKEY)
    assert record is not None
    assert record.name == "Codex development agent"
    assert record.roles == ("package-developer",)
    assert Scope.PACKAGES_TEST in record.scopes
    assert record.expires == datetime(2099, 12, 31, tzinfo=timezone.utc)
    assert not record.is_expired()


def test_loads_hex_keyed_entry_without_expiry(tmp_path: Path):
    toml_path = tmp_path / "identity.toml"
    toml_path.write_text(
        f"""
[identity."{HEX_PUBKEY}"]
name = "Admin"
roles = ["administrator"]
"""
    )
    store = IdentityStore.load(toml_path)
    record = store.lookup(HEX_PUBKEY)
    assert record is not None
    assert not record.is_expired()


def test_expired_record_reports_expired(tmp_path: Path):
    toml_path = tmp_path / "identity.toml"
    toml_path.write_text(
        f"""
[identity."{HEX_PUBKEY}"]
name = "Old agent"
roles = ["readonly"]
expires = "2000-01-01T00:00:00+00:00"
"""
    )
    store = IdentityStore.load(toml_path)
    record = store.lookup(HEX_PUBKEY)
    assert record is not None
    assert record.is_expired()


def test_unknown_role_raises_config_error(tmp_path: Path):
    toml_path = tmp_path / "identity.toml"
    toml_path.write_text(
        f"""
[identity."{HEX_PUBKEY}"]
name = "Broken"
roles = ["superuser"]
"""
    )
    with pytest.raises(IdentityConfigError):
        IdentityStore.load(toml_path)


def test_nsec_key_rejected_loudly(tmp_path: Path):
    # A private key accidentally pasted where a pubkey belongs must never
    # be silently accepted (PLAN.md Phase 9: never store a private key).
    toml_path = tmp_path / "identity.toml"
    toml_path.write_text(
        """
[identity."nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"]
name = "Oops"
roles = ["administrator"]
"""
    )
    with pytest.raises(IdentityConfigError, match="nsec"):
        IdentityStore.load(toml_path)


def test_malformed_toml_raises_config_error(tmp_path: Path):
    toml_path = tmp_path / "identity.toml"
    toml_path.write_text("this is not [valid toml")
    with pytest.raises(IdentityConfigError):
        IdentityStore.load(toml_path)
