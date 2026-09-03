"""Shared helpers for building signed Nostr/NIP-98 events in tests."""

from __future__ import annotations

import hashlib
import json
import time

from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nostr import NostrEvent, compute_event_id


def new_keypair() -> tuple[PrivateKey, str]:
    """Return (private_key, x_only_pubkey_hex)."""
    sk = PrivateKey()
    pubkey_hex = PublicKeyXOnly.from_valid_secret(sk.secret).format().hex()
    return sk, pubkey_hex


def sign_event(sk: PrivateKey, *, pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str = "") -> NostrEvent:
    unsigned = NostrEvent(
        id="0" * 64,
        pubkey=pubkey,
        created_at=created_at,
        kind=kind,
        tags=tags,
        content=content,
        sig="0" * 128,
    )
    event_id = compute_event_id(unsigned)
    sig = sk.sign_schnorr(bytes.fromhex(event_id)).hex()
    return NostrEvent(
        id=event_id,
        pubkey=pubkey,
        created_at=created_at,
        kind=kind,
        tags=tags,
        content=content,
        sig=sig,
    )


def make_nip98_authorization_header(
    sk: PrivateKey,
    pubkey: str,
    *,
    method: str,
    url: str,
    body: bytes = b"",
    created_at: int | None = None,
    include_payload_tag: bool = True,
) -> str:
    import base64

    created_at = int(time.time()) if created_at is None else created_at
    tags = [["u", url], ["method", method]]
    if include_payload_tag and body:
        tags.append(["payload", hashlib.sha256(body).hexdigest()])

    event = sign_event(sk, pubkey=pubkey, created_at=created_at, kind=27235, tags=tags)
    encoded = base64.b64encode(json.dumps(event.model_dump()).encode()).decode()
    return f"Nostr {encoded}"
