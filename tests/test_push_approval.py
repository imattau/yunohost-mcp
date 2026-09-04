"""Unit tests for push_approval.py's pure logic: the human-readable
approval content it builds, and the verification that decides whether a
signed event actually proves the configured owner approved one exact
ticket. The live NIP-46 round trip itself needs a real signer app and is
out of scope here - exercised manually, not here (same boundary
test_approve.py draws for approve.py's own live-network pieces).
"""

from __future__ import annotations

from yunohost_mcp.push_approval import PUSH_APPROVAL_KIND, _build_push_content, _verify_and_extract


def test_build_push_content_includes_tool_hash_and_confirmation_id():
    content = _build_push_content(
        tool="system_upgrade",
        operation_plan={"action": "upgrade system packages", "warning": "may restart services"},
        operation_hash="abc123",
        confirmation_id="confirm-xyz",
    )
    assert "system_upgrade" in content
    assert "upgrade system packages" in content
    assert "may restart services" in content
    assert "abc123" in content
    assert "confirm-xyz" in content


def test_build_push_content_omits_missing_plan_fields():
    content = _build_push_content(
        tool="backup_restore", operation_plan={}, operation_hash="hash1", confirmation_id="confirm-1"
    )
    assert "action:" not in content
    assert "warning:" not in content
    assert "hash1" in content


class _FakeTag:
    def __init__(self, parts):
        self._parts = parts

    def to_vec(self):
        return self._parts


class _FakePublicKey:
    def __init__(self, hex_value):
        self._hex = hex_value

    def to_hex(self):
        return self._hex


class _FakeEvent:
    # Event.tags() returns a plain list of Tag directly in this nostr_sdk
    # build, not a wrapper with its own .to_vec() - _verify_and_extract's
    # original code got exactly this wrong and crashed against a real
    # signed event in production; this fake mirrors the real shape now
    # rather than the earlier (wrong) idealized one that let it slip by.
    def __init__(self, *, valid=True, author_hex="owner", tags=None):
        self._valid = valid
        self._author = _FakePublicKey(author_hex)
        self._tags = tags or []

    def verify(self):
        return self._valid

    def author(self):
        return self._author

    def tags(self):
        return self._tags


def _matching_tags(confirmation_id="confirm-1", operation_hash="hash1"):
    return [_FakeTag(["confirmation_id", confirmation_id]), _FakeTag(["operation_hash", operation_hash])]


def test_verify_and_extract_accepts_valid_matching_owner_signature():
    event = _FakeEvent(valid=True, author_hex="owner", tags=_matching_tags())
    assert _verify_and_extract(
        event, owner_pubkey_hex="owner", confirmation_id="confirm-1", operation_hash="hash1"
    ) is True


def test_verify_and_extract_rejects_invalid_signature():
    event = _FakeEvent(valid=False, author_hex="owner", tags=_matching_tags())
    assert _verify_and_extract(
        event, owner_pubkey_hex="owner", confirmation_id="confirm-1", operation_hash="hash1"
    ) is False


def test_verify_and_extract_rejects_wrong_signer():
    event = _FakeEvent(valid=True, author_hex="someone-else", tags=_matching_tags())
    assert _verify_and_extract(
        event, owner_pubkey_hex="owner", confirmation_id="confirm-1", operation_hash="hash1"
    ) is False


def test_verify_and_extract_rejects_mismatched_confirmation_id():
    event = _FakeEvent(valid=True, author_hex="owner", tags=_matching_tags(confirmation_id="confirm-different"))
    assert _verify_and_extract(
        event, owner_pubkey_hex="owner", confirmation_id="confirm-1", operation_hash="hash1"
    ) is False


def test_verify_and_extract_rejects_mismatched_operation_hash():
    event = _FakeEvent(valid=True, author_hex="owner", tags=_matching_tags(operation_hash="different-hash"))
    assert _verify_and_extract(
        event, owner_pubkey_hex="owner", confirmation_id="confirm-1", operation_hash="hash1"
    ) is False


def test_verify_and_extract_rejects_missing_tags():
    event = _FakeEvent(valid=True, author_hex="owner", tags=[])
    assert _verify_and_extract(
        event, owner_pubkey_hex="owner", confirmation_id="confirm-1", operation_hash="hash1"
    ) is False


def test_push_approval_kind_is_distinct_from_nip98():
    assert PUSH_APPROVAL_KIND != 27235


def test_verify_and_extract_accepts_a_real_signed_nostr_sdk_event():
    # Regression test for a real production bug: _verify_and_extract
    # originally called signed.tags().to_vec(), assuming Event.tags()
    # returns a Tags wrapper - it doesn't, it's already a plain list of
    # Tag, and the mistake only surfaced as a crash against a real signed
    # event (the fakes above previously mirrored the same wrong
    # assumption, so they never would have caught this). Exercises the
    # actual nostr_sdk Event/EventBuilder/Keys, no fakes at all.
    from nostr_sdk import EventBuilder, Keys, Kind, Tag

    from yunohost_mcp.push_approval import PUSH_APPROVAL_KIND

    keys = Keys.generate()
    event = (
        EventBuilder(Kind(PUSH_APPROVAL_KIND), "approve?")
        .tags([Tag.parse(["confirmation_id", "confirm-1"]), Tag.parse(["operation_hash", "hash1"])])
        .finalize(keys)
    )
    assert (
        _verify_and_extract(
            event,
            owner_pubkey_hex=keys.public_key().to_hex(),
            confirmation_id="confirm-1",
            operation_hash="hash1",
        )
        is True
    )
