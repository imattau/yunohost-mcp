from __future__ import annotations

from pathlib import Path

import pytest

from yunohost_mcp.auth.identity import IdentityStore
from yunohost_mcp.auth.npub import hex_to_npub
from yunohost_mcp.auth.owner import OwnerConfigError, resolve_owner_pubkey

HEX_PUBKEY = "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"
OTHER_HEX_PUBKEY = "aa" * 32


def _store_with_administrators(tmp_path: Path, pubkeys: list[str]) -> IdentityStore:
    toml_path = tmp_path / "identity.toml"
    entries = "\n".join(
        f'[identity."{pubkey}"]\nname = "Admin {i}"\nroles = ["administrator"]\n' for i, pubkey in enumerate(pubkeys)
    )
    toml_path.write_text(entries)
    return IdentityStore.load(toml_path)


def test_explicit_hex_owner_npub_wins_over_bootstrap_fallback(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [OTHER_HEX_PUBKEY])
    assert resolve_owner_pubkey(owner_npub=HEX_PUBKEY, identity_store=store) == HEX_PUBKEY


def test_explicit_npub_owner_is_decoded_to_hex(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [])
    npub = hex_to_npub(HEX_PUBKEY)
    assert resolve_owner_pubkey(owner_npub=npub, identity_store=store) == HEX_PUBKEY


def test_explicit_owner_npub_rejects_nsec(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [])
    with pytest.raises(OwnerConfigError, match="nsec"):
        resolve_owner_pubkey(
            owner_npub="nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
            identity_store=store,
        )


def test_explicit_owner_npub_rejects_malformed_npub(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [])
    with pytest.raises(OwnerConfigError):
        resolve_owner_pubkey(owner_npub="npub1notreallyvalid", identity_store=store)


def test_bootstrap_fallback_to_sole_administrator(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [HEX_PUBKEY])
    assert resolve_owner_pubkey(owner_npub=None, identity_store=store) == HEX_PUBKEY


def test_bootstrap_fallback_is_none_when_no_administrator_exists(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [])
    assert resolve_owner_pubkey(owner_npub=None, identity_store=store) is None


def test_bootstrap_fallback_is_none_when_administrators_are_ambiguous(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [HEX_PUBKEY, OTHER_HEX_PUBKEY])
    assert resolve_owner_pubkey(owner_npub=None, identity_store=store) is None


def test_empty_owner_npub_falls_back_like_unset(tmp_path: Path):
    store = _store_with_administrators(tmp_path, [HEX_PUBKEY])
    assert resolve_owner_pubkey(owner_npub="", identity_store=store) == HEX_PUBKEY
