"""Unit tests for notify.py (owner-approval-plan.md's optional,
best-effort NIP-17 owner notification). The event-building and relay-list
parsing are pure and tested directly; the live relay publish is not
covered here (needs a real relay, same caveat as approve.py's pairing
flow) - notify_owner_best_effort's own catch-all is what's tested instead,
since "never raises" is the contract the rest of the system depends on.
"""

from __future__ import annotations

import logging

from nostr_sdk import Keys

from yunohost_mcp.notify import build_notification_event, notify_owner_best_effort, parse_relay_list

NIP17_GIFT_WRAP_KIND = 1059


def test_parse_relay_list_splits_and_strips():
    assert parse_relay_list("wss://a.example, wss://b.example ,, ") == ["wss://a.example", "wss://b.example"]


def test_parse_relay_list_empty_string_is_empty_list():
    assert parse_relay_list("") == []


def test_build_notification_event_is_a_gift_wrapped_nip17_event():
    server_keys = Keys.generate()
    owner_keys = Keys.generate()
    event = build_notification_event(
        server_secret_key_hex=server_keys.secret_key().to_hex(),
        owner_pubkey_hex=owner_keys.public_key().to_hex(),
        confirmation_id="confirm-abc123",
        tool="system.upgrade",
        expires_at=1234567890.0,
    )
    assert event.kind().as_u16() == NIP17_GIFT_WRAP_KIND
    # A gift wrap's own content is opaque (sealed+encrypted) - it must not
    # leak the confirmation_id or tool name in plaintext on the relay.
    assert "confirm-abc123" not in event.as_json()
    assert "system.upgrade" not in event.as_json()


def test_notify_owner_best_effort_is_a_noop_with_no_relays():
    # Must not attempt anything (no network, no key parsing) when disabled -
    # garbage key/pubkey values would otherwise raise before the empty
    # relay list is even checked.
    notify_owner_best_effort(
        server_secret_key_hex="not-a-real-key",
        owner_pubkey_hex="not-a-real-pubkey",
        relays=[],
        confirmation_id="confirm-abc123",
        tool="system.upgrade",
        expires_at=0.0,
    )


def test_notify_owner_best_effort_never_raises_on_failure(caplog):
    # A malformed key is a real failure mode (misconfiguration) - this
    # must still not raise, only log, per the module's "never raises"
    # contract that server.py's hook wiring depends on.
    with caplog.at_level(logging.WARNING):
        notify_owner_best_effort(
            server_secret_key_hex="not-a-real-key",
            owner_pubkey_hex="not-a-real-pubkey",
            relays=["wss://relay.example"],
            confirmation_id="confirm-abc123",
            tool="system.upgrade",
            expires_at=0.0,
        )
    assert any("owner approval notification failed" in record.message for record in caplog.records)
