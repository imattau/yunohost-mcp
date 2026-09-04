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
    _build_parser,
    _confirm_interactively,
    _parse_relay_urls_from_event_tags,
    _print_status,
    resolve_pair_relays,
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


class _Args:
    def __init__(self, session_file):
        self.session_file = str(session_file)


def test_status_reports_unpaired_for_missing_session(tmp_path, capsys):
    _print_status(_Args(tmp_path / "no-session.json"))
    assert capsys.readouterr().out.strip() == "paired: false"


def test_status_reports_unpaired_for_session_without_bunker_uri(tmp_path, capsys):
    path = tmp_path / "session.json"
    ApprovalSession.fresh().save(path)
    _print_status(_Args(path))
    assert capsys.readouterr().out.strip() == "paired: false"


def test_status_reports_paired_and_signer_pubkey(tmp_path, capsys):
    path = tmp_path / "session.json"
    session = ApprovalSession.fresh()
    session.bunker_uri = "bunker://deadbeef1234?relay=wss://relay.example&secret=abc"
    session.save(path)

    _print_status(_Args(path))
    out = capsys.readouterr().out
    assert "paired: true" in out
    assert "signer_pubkey: deadbeef1234" in out


def test_approve_subcommand_accepts_yes_flag():
    parser = _build_parser()
    args = parser.parse_args(["approve", "--server", "https://example.test/mcp", "--confirmation-id", "confirm-x", "--yes"])
    assert args.yes is True


def test_approve_subcommand_defaults_yes_to_false():
    parser = _build_parser()
    args = parser.parse_args(["approve", "--server", "https://example.test/mcp", "--confirmation-id", "confirm-x"])
    assert args.yes is False


def test_status_subcommand_parses():
    parser = _build_parser()
    args = parser.parse_args(["status"])
    assert args.action == "status"


def test_pair_subcommand_accepts_owner_npub_and_extra_relay():
    parser = _build_parser()
    args = parser.parse_args(
        ["pair", "--owner-npub", "npub1example", "--extra-relay", "wss://a.example", "--extra-relay", "wss://b.example"]
    )
    assert args.owner_npub == "npub1example"
    assert args.extra_relay == ["wss://a.example", "wss://b.example"]


def test_resolve_pair_relays_explicit_relay_overrides_everything():
    result = resolve_pair_relays(
        explicit=["wss://explicit.example"],
        extra=["wss://extra.example"],
        discovered=["wss://discovered.example"],
        defaults=["wss://default.example"],
    )
    assert result == ["wss://explicit.example"]


def test_resolve_pair_relays_prefers_discovered_over_defaults():
    result = resolve_pair_relays(explicit=None, extra=[], discovered=["wss://discovered.example"], defaults=["wss://default.example"])
    assert result == ["wss://discovered.example"]


def test_resolve_pair_relays_falls_back_to_defaults_when_nothing_discovered():
    result = resolve_pair_relays(explicit=None, extra=[], discovered=[], defaults=["wss://default.example"])
    assert result == ["wss://default.example"]


def test_resolve_pair_relays_folds_in_extra_alongside_discovered_or_defaults():
    result = resolve_pair_relays(
        explicit=None, extra=["wss://extra.example"], discovered=["wss://discovered.example"], defaults=["wss://default.example"]
    )
    assert result == ["wss://discovered.example", "wss://extra.example"]


def test_resolve_pair_relays_dedupes():
    result = resolve_pair_relays(
        explicit=None,
        extra=["wss://discovered.example"],
        discovered=["wss://discovered.example"],
        defaults=["wss://default.example"],
    )
    assert result == ["wss://discovered.example"]


class _FakeTag:
    def __init__(self, parts):
        self._parts = parts

    def to_vec(self):
        return self._parts


class _FakeTags:
    def __init__(self, tags):
        self._tags = tags

    def to_vec(self):
        return self._tags


class _FakeEvent:
    def __init__(self, tags):
        self._tags = _FakeTags(tags)

    def tags(self):
        return self._tags


def test_parse_relay_urls_from_event_tags_collects_r_tags():
    event = _FakeEvent(
        [
            _FakeTag(["r", "wss://relay-a.example"]),
            _FakeTag(["r", "wss://relay-b.example", "write"]),
            _FakeTag(["p", "somepubkey"]),
        ]
    )
    assert _parse_relay_urls_from_event_tags(event) == ["wss://relay-a.example", "wss://relay-b.example"]


def test_parse_relay_urls_from_event_tags_ignores_malformed_r_tags():
    event = _FakeEvent([_FakeTag(["r"])])
    assert _parse_relay_urls_from_event_tags(event) == []
