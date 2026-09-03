"""Unit tests for the parts of approve.py (owner-approval-plan.md's NIP-46
helper) that don't need a live relay or a real remote signer: session
persistence, the nostrconnect:// URI it builds for pairing, and the
interactive-confirmation gate. The actual NIP-46 round trip (pairing,
signing) needs a real signer app and is out of scope for this suite -
exercised manually, not here.
"""

from __future__ import annotations

import json
import stat
import urllib.parse

import pytest
from nostr_sdk import Keys

from yunohost_mcp.approve import (
    ApprovalSession,
    _build_nostrconnect_uri,
    _confirm_interactively,
)


def test_fresh_session_has_no_bunker_uri_yet():
    session = ApprovalSession.fresh()
    assert session.bunker_uri is None
    # A valid hex secret key, parseable back into real Keys.
    Keys.parse(session.app_secret_key)


def test_fresh_sessions_get_distinct_app_keys():
    a = ApprovalSession.fresh()
    b = ApprovalSession.fresh()
    assert a.app_secret_key != b.app_secret_key


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "session.json"
    session = ApprovalSession.fresh()
    session.bunker_uri = "bunker://deadbeef?relay=wss://relay.example&secret=abc"
    session.save(path)

    loaded = ApprovalSession.load(path)
    assert loaded is not None
    assert loaded.app_secret_key == session.app_secret_key
    assert loaded.bunker_uri == session.bunker_uri


def test_load_missing_session_returns_none(tmp_path):
    assert ApprovalSession.load(tmp_path / "does-not-exist.json") is None


def test_save_sets_owner_only_permissions(tmp_path):
    path = tmp_path / "session.json"
    ApprovalSession.fresh().save(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_save_creates_missing_parent_directories(tmp_path):
    path = tmp_path / "nested" / "dir" / "session.json"
    ApprovalSession.fresh().save(path)
    assert path.exists()


def test_app_keys_reparses_the_same_identity():
    session = ApprovalSession.fresh()
    keys = session.app_keys()
    assert keys.secret_key().to_hex() == session.app_secret_key


def test_nostrconnect_uri_has_expected_scheme_and_pubkey():
    keys = Keys.generate()
    pubkey_hex = keys.public_key().to_hex()
    uri = _build_nostrconnect_uri(app_pubkey_hex=pubkey_hex, relays=["wss://relay.example"], secret="s3cr3t")
    assert uri.startswith(f"nostrconnect://{pubkey_hex}?")


def test_nostrconnect_uri_includes_narrowest_perms_and_secret():
    keys = Keys.generate()
    uri = _build_nostrconnect_uri(
        app_pubkey_hex=keys.public_key().to_hex(), relays=["wss://relay.example"], secret="s3cr3t"
    )
    assert "perms=sign_event%3A27235" in uri
    assert "secret=s3cr3t" in uri


def test_nostrconnect_uri_carries_app_name_as_json_metadata_not_a_flat_name_param():
    # rust-nostr's own NostrConnectUri.parse (nostr-sdk 0.45) has no plain
    # `name=` query param for this scheme - the app name must be inside a
    # JSON-encoded `metadata` param, or parsing silently ignores it and
    # (separately) rejects the URI for missing metadata entirely.
    keys = Keys.generate()
    uri = _build_nostrconnect_uri(
        app_pubkey_hex=keys.public_key().to_hex(), relays=["wss://relay.example"], secret="s3cr3t"
    )
    decoded_query = urllib.parse.parse_qs(uri.split("?", 1)[1])
    assert "name" not in decoded_query
    metadata = json.loads(decoded_query["metadata"][0])
    assert metadata["name"] == "yunohost-mcp-approve"


def test_nostrconnect_uri_repeats_relay_param_per_relay():
    keys = Keys.generate()
    uri = _build_nostrconnect_uri(
        app_pubkey_hex=keys.public_key().to_hex(),
        relays=["wss://relay-one.example", "wss://relay-two.example"],
        secret="s3cr3t",
    )
    assert uri.count("relay=") == 2


def test_nostrconnect_uri_is_parseable_by_nostr_sdk():
    from nostr_sdk import NostrConnectUri

    keys = Keys.generate()
    uri = _build_nostrconnect_uri(
        app_pubkey_hex=keys.public_key().to_hex(), relays=["wss://relay.example"], secret="s3cr3t"
    )
    NostrConnectUri.parse(uri)  # must not raise


def test_nostrconnect_uri_can_construct_a_real_nostrconnect_client():
    # Catches constructor-level mismatches (not just NostrConnectUri.parse)
    # without needing a live relay or signer - NostrConnect() itself does
    # not perform network I/O until an async method is awaited.
    from datetime import timedelta

    from nostr_sdk import NostrConnect, NostrConnectUri

    app_keys = Keys.generate()
    uri = _build_nostrconnect_uri(
        app_pubkey_hex=app_keys.public_key().to_hex(), relays=["wss://relay.example"], secret="s3cr3t"
    )
    NostrConnect(NostrConnectUri.parse(uri), app_keys, timedelta(seconds=1), None)


def test_confirm_interactively_requires_exact_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert _confirm_interactively() is False

    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert _confirm_interactively() is True

    monkeypatch.setattr("builtins.input", lambda _: "YES")
    assert _confirm_interactively() is True


def test_confirm_interactively_treats_eof_as_declined(monkeypatch):
    def raise_eof(_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert _confirm_interactively() is False


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_confirm_interactively_declines_anything_but_yes(monkeypatch, answer):
    monkeypatch.setattr("builtins.input", lambda _: answer)
    assert _confirm_interactively() is False
