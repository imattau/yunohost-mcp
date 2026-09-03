"""Nostr event model, id computation, and signature verification (NIP-01).

This module knows nothing about HTTP or NIP-98 — it is the generic
"is this a validly-signed Nostr event" primitive that nip98.py builds on.
"""

from __future__ import annotations

import hashlib
import json

from coincurve import PublicKeyXOnly
from pydantic import BaseModel, field_validator

HEX32_LEN = 64  # 32 bytes as hex
HEX64_LEN = 128  # 64 bytes as hex (schnorr signature)


class NostrEventError(ValueError):
    """A Nostr event is malformed, has a bad id, or has an invalid signature."""


class NostrEvent(BaseModel):
    """A signed Nostr event (NIP-01), as delivered over the wire."""

    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    sig: str

    @field_validator("id", "pubkey")
    @classmethod
    def _validate_hex32(cls, v: str) -> str:
        if len(v) != HEX32_LEN or not _is_hex(v):
            raise ValueError("expected 32-byte lowercase hex string")
        return v

    @field_validator("sig")
    @classmethod
    def _validate_sig_hex(cls, v: str) -> str:
        if len(v) != HEX64_LEN or not _is_hex(v):
            raise ValueError("expected 64-byte lowercase hex string")
        return v

    def tag(self, name: str) -> str | None:
        """First value of the first tag matching `name`, if any."""
        for t in self.tags:
            if len(t) >= 2 and t[0] == name:
                return t[1]
        return None


def _is_hex(v: str) -> bool:
    try:
        bytes.fromhex(v)
    except ValueError:
        return False
    return v == v.lower()


def compute_event_id(event: NostrEvent) -> str:
    """NIP-01 event id: sha256 of the canonical serialization form.

    Canonical form is [0, pubkey, created_at, kind, tags, content] serialized
    with no extra whitespace and only the JSON-mandated escapes (this is what
    `json.dumps(..., separators=(",", ":"), ensure_ascii=False)` produces).
    """
    serialized = json.dumps(
        [0, event.pubkey, event.created_at, event.kind, event.tags, event.content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_event(event: NostrEvent) -> None:
    """Verify an event's id matches its content and its signature is valid.

    Raises NostrEventError on any failure. Does not check kind, tags, or
    timestamp freshness — that's NIP-98-specific and lives in nip98.py.
    """
    expected_id = compute_event_id(event)
    if event.id != expected_id:
        raise NostrEventError(f"event id mismatch: got {event.id}, computed {expected_id}")

    try:
        pubkey_bytes = bytes.fromhex(event.pubkey)
        sig_bytes = bytes.fromhex(event.sig)
        message = bytes.fromhex(event.id)
        verifying_key = PublicKeyXOnly(pubkey_bytes)
        ok = verifying_key.verify(sig_bytes, message)
    except Exception as exc:  # noqa: BLE001 - any crypto-library failure means "invalid"
        raise NostrEventError(f"signature verification failed: {exc}") from exc

    if not ok:
        raise NostrEventError("invalid schnorr signature")
