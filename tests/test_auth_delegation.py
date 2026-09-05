from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from tests.auth_helpers import make_delegation_event, new_keypair
from yunohost_mcp.auth.delegation import DelegationError, resolve_delegated_identity, verify_delegation_event
from yunohost_mcp.auth.identity import IdentityRecord, IdentityStore
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.policy.roles import scopes_for_roles
from yunohost_mcp.policy.scopes import Scope

SERVER_PUBKEY = "s" * 64


def make_identity_store(delegator_pubkey: str, *, roles=("readonly",), expires=None) -> IdentityStore:
    record = IdentityRecord(
        pubkey=delegator_pubkey,
        name="owner",
        roles=roles,
        scopes=scopes_for_roles(roles),
        expires=expires,
    )
    return IdentityStore({delegator_pubkey: record})


def _future(seconds: int = 3600) -> int:
    return int(time.time()) + seconds


def test_valid_delegation_verifies():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    claim = verify_delegation_event(
        event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
    )
    assert claim.delegator_pubkey == delegator
    assert claim.delegate_pubkey == delegate
    assert claim.requested_scopes == {Scope.APPS_READ}


def test_wrong_delegate_pubkey_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    _, someone_else = new_keypair()
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    with pytest.raises(DelegationError, match="does not match"):
        verify_delegation_event(
            event,
            expected_delegate_pubkey=someone_else,
            server_pubkey_hex=SERVER_PUBKEY,
            revocation_store=RevocationStore(frozenset()),
        )


def test_wrong_server_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    with pytest.raises(DelegationError, match="targets server"):
        verify_delegation_event(
            event,
            expected_delegate_pubkey=delegate,
            server_pubkey_hex="different-server" + "s" * 55,
            revocation_store=RevocationStore(frozenset()),
        )


def test_expired_delegation_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    event = make_delegation_event(
        sk,
        delegator,
        delegate_pubkey=delegate,
        server_pubkey=SERVER_PUBKEY,
        scopes=["apps.read"],
        expires_at=int(time.time()) - 10,
        created_at=int(time.time()) - 20,
    )
    with pytest.raises(DelegationError, match="expired"):
        verify_delegation_event(
            event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
        )


def test_delegation_exceeding_max_lifetime_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    now = int(time.time())
    event = make_delegation_event(
        sk,
        delegator,
        delegate_pubkey=delegate,
        server_pubkey=SERVER_PUBKEY,
        scopes=["apps.read"],
        expires_at=now + 400 * 24 * 3600,  # far beyond the 30-day cap
        created_at=now,
    )
    with pytest.raises(DelegationError, match="exceeds the maximum"):
        verify_delegation_event(
            event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
        )


def test_unknown_scope_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["not.a.real.scope"], expires_at=_future()
    )
    with pytest.raises(DelegationError, match="unknown scope"):
        verify_delegation_event(
            event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
        )


def test_revoked_delegation_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    revocation_store = RevocationStore(frozenset({event.id}))
    with pytest.raises(DelegationError, match="revoked"):
        verify_delegation_event(
            event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=revocation_store
        )


def test_delegation_with_no_expiry_tag_rejected():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    # Strip the expiry tag after signing is impossible without invalidating
    # the signature - instead build one with a tampered tag list directly,
    # matching the "no expiry" structural case at the id/sig level: this
    # would fail signature verification for any *tampering*, so instead
    # assert the code path exists by constructing via a helper that omits it.
    from tests.auth_helpers import sign_event
    from yunohost_mcp.auth.delegation import DELEGATION_KIND

    no_expiry_event = sign_event(
        sk,
        pubkey=delegator,
        created_at=int(time.time()),
        kind=DELEGATION_KIND,
        tags=[["p", delegate], ["server", SERVER_PUBKEY], ["scope", "apps.read"]],
    )
    with pytest.raises(DelegationError, match="expiry"):
        verify_delegation_event(
            no_expiry_event,
            expected_delegate_pubkey=delegate,
            server_pubkey_hex=SERVER_PUBKEY,
            revocation_store=RevocationStore(frozenset()),
        )


def test_resolve_delegated_identity_intersects_scopes_with_delegator():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    # Delegator only has "readonly" scopes (apps.read among them, not apps.install).
    identity_store = make_identity_store(delegator, roles=("readonly",))
    event = make_delegation_event(
        sk,
        delegator,
        delegate_pubkey=delegate,
        server_pubkey=SERVER_PUBKEY,
        scopes=["apps.read", "apps.install"],  # requests more than the delegator has
        expires_at=_future(),
    )
    claim = verify_delegation_event(
        event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
    )
    record = resolve_delegated_identity(claim, identity_store=identity_store)
    assert record.pubkey == delegate
    assert Scope.APPS_READ in record.scopes
    assert Scope.APPS_INSTALL not in record.scopes  # cannot grant what the delegator lacks


def test_resolve_delegated_identity_rejects_unknown_delegator():
    _, delegate = new_keypair()
    sk, delegator = new_keypair()
    empty_store = IdentityStore({})
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    claim = verify_delegation_event(
        event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
    )
    with pytest.raises(DelegationError, match="not in identity.toml"):
        resolve_delegated_identity(claim, identity_store=empty_store)


def test_resolve_delegated_identity_clips_expiry_to_delegators_own():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    delegator_expires = datetime.now(timezone.utc) + timedelta(seconds=100)
    identity_store = make_identity_store(delegator, roles=("readonly",), expires=delegator_expires)
    event = make_delegation_event(
        sk,
        delegator,
        delegate_pubkey=delegate,
        server_pubkey=SERVER_PUBKEY,
        scopes=["apps.read"],
        expires_at=_future(seconds=99999),  # much longer than the delegator's own remaining validity
    )
    claim = verify_delegation_event(
        event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
    )
    record = resolve_delegated_identity(claim, identity_store=identity_store)
    assert record.expires is not None
    assert record.expires <= delegator_expires + timedelta(seconds=1)


def test_resolve_delegated_identity_rejects_expired_delegator():
    sk, delegator = new_keypair()
    _, delegate = new_keypair()
    identity_store = make_identity_store(
        delegator, roles=("readonly",), expires=datetime.now(timezone.utc) - timedelta(days=1)
    )
    event = make_delegation_event(
        sk, delegator, delegate_pubkey=delegate, server_pubkey=SERVER_PUBKEY, scopes=["apps.read"], expires_at=_future()
    )
    claim = verify_delegation_event(
        event, expected_delegate_pubkey=delegate, server_pubkey_hex=SERVER_PUBKEY, revocation_store=RevocationStore(frozenset())
    )
    with pytest.raises(DelegationError, match="expired"):
        resolve_delegated_identity(claim, identity_store=identity_store)
