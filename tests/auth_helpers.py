"""Shared helpers for building signed Nostr/NIP-98 events in tests.

sign_event() itself is imported from yunohost_mcp.auth.nostr - the real,
shipped implementation (also used by auth/signing.py's ClientIdentity for
the actual client bridge) - rather than reimplemented here, so every test
using these helpers is exercising production signing code, not a parallel
copy of it that could quietly drift from what real callers get.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nostr import NostrEvent, sign_event

__all__ = [
    "new_keypair",
    "sign_event",
    "make_nip98_authorization_header",
    "make_delegation_event",
    "make_delegation_header",
]


def new_keypair() -> tuple[PrivateKey, str]:
    """Return (private_key, x_only_pubkey_hex)."""
    sk = PrivateKey()
    pubkey_hex = PublicKeyXOnly.from_valid_secret(sk.secret).format().hex()
    return sk, pubkey_hex


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
    """Thin wrapper over the real sign_event(), with the timestamp/payload-tag
    overrides several tests need (stale timestamps, a missing payload tag)
    that the production ClientIdentity.sign_nip98() deliberately doesn't
    expose - those are footguns for a real client, not something to build
    in for real use, but exactly what tests of the *server's* checks need.
    """
    created_at = int(time.time()) if created_at is None else created_at
    tags = [["u", url], ["method", method]]
    if include_payload_tag and body:
        tags.append(["payload", hashlib.sha256(body).hexdigest()])

    event = sign_event(sk, pubkey=pubkey, created_at=created_at, kind=27235, tags=tags)
    encoded = base64.b64encode(json.dumps(event.model_dump()).encode()).decode()
    return f"Nostr {encoded}"


def make_delegation_event(
    delegator_sk: PrivateKey,
    delegator_pubkey: str,
    *,
    delegate_pubkey: str,
    server_pubkey: str,
    scopes: list[str],
    expires_at: int,
    created_at: int | None = None,
) -> NostrEvent:
    from yunohost_mcp.auth.delegation import DELEGATION_KIND

    created_at = int(time.time()) if created_at is None else created_at
    tags = [["p", delegate_pubkey], ["server", server_pubkey], ["expiry", str(expires_at)]]
    tags += [["scope", s] for s in scopes]
    return sign_event(delegator_sk, pubkey=delegator_pubkey, created_at=created_at, kind=DELEGATION_KIND, tags=tags)


def make_delegation_header(*args, **kwargs) -> str:
    event = make_delegation_event(*args, **kwargs)
    return base64.b64encode(json.dumps(event.model_dump()).encode()).decode()
