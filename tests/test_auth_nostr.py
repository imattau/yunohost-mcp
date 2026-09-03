from __future__ import annotations

import time

import pytest

from tests.auth_helpers import new_keypair, sign_event
from yunohost_mcp.auth.nostr import NostrEventError, verify_event


def test_valid_event_verifies():
    sk, pubkey = new_keypair()
    event = sign_event(sk, pubkey=pubkey, created_at=int(time.time()), kind=1, tags=[], content="hello")
    verify_event(event)  # should not raise


def test_tampered_content_fails_id_check():
    sk, pubkey = new_keypair()
    event = sign_event(sk, pubkey=pubkey, created_at=int(time.time()), kind=1, tags=[], content="hello")
    tampered = event.model_copy(update={"content": "goodbye"})
    with pytest.raises(NostrEventError, match="event id mismatch"):
        verify_event(tampered)


def test_wrong_signer_fails_signature_check():
    sk1, pubkey1 = new_keypair()
    _sk2, pubkey2 = new_keypair()
    event = sign_event(sk1, pubkey=pubkey1, created_at=int(time.time()), kind=1, tags=[], content="hello")
    # Claim it came from a different pubkey but keep sk1's signature: id changes
    # to match the new pubkey, but the signature was made by sk1 over the old id.
    forged = event.model_copy(update={"pubkey": pubkey2})
    with pytest.raises(NostrEventError):
        verify_event(forged)
