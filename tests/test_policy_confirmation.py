from __future__ import annotations

import time

import pytest

from yunohost_mcp.policy.confirmation import ConfirmationError, ConfirmationStore


def test_consume_valid_ticket():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={"app": "nextcloud"}, plan={"action": "remove"})
    consumed = store.consume(ticket.confirmation_id, pubkey="abc", tool="apps.remove", arguments={"app": "nextcloud"})
    assert consumed.confirmation_id == ticket.confirmation_id


def test_ticket_is_one_shot():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={"app": "x"}, plan={})
    store.consume(ticket.confirmation_id, pubkey="abc", tool="apps.remove", arguments={"app": "x"})
    with pytest.raises(ConfirmationError):
        store.consume(ticket.confirmation_id, pubkey="abc", tool="apps.remove", arguments={"app": "x"})


def test_unknown_id_rejected():
    store = ConfirmationStore()
    with pytest.raises(ConfirmationError):
        store.consume("confirm-doesnotexist", pubkey="abc", tool="apps.remove", arguments={})


def test_wrong_pubkey_rejected():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={"app": "x"}, plan={})
    with pytest.raises(ConfirmationError, match="different identity"):
        store.consume(ticket.confirmation_id, pubkey="someone-else", tool="apps.remove", arguments={"app": "x"})


def test_wrong_tool_rejected():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={"app": "x"}, plan={})
    with pytest.raises(ConfirmationError, match="different tool"):
        store.consume(ticket.confirmation_id, pubkey="abc", tool="backups.restore", arguments={"app": "x"})


def test_mismatched_arguments_rejected():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={"app": "nextcloud"}, plan={})
    with pytest.raises(ConfirmationError, match="exact arguments"):
        store.consume(ticket.confirmation_id, pubkey="abc", tool="apps.remove", arguments={"app": "wordpress"})


def test_expired_ticket_rejected():
    store = ConfirmationStore(ttl_seconds=1)
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={}, plan={})
    time.sleep(1.1)
    with pytest.raises(ConfirmationError, match="expired"):
        store.consume(ticket.confirmation_id, pubkey="abc", tool="apps.remove", arguments={})


# -- Phase 13: owner co-signing --------------------------------------------


def test_consume_without_owner_approval_required_ignores_approval_state():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="apps.remove", arguments={"app": "x"}, plan={})
    consumed = store.consume(
        ticket.confirmation_id, pubkey="abc", tool="apps.remove", arguments={"app": "x"}, require_owner_approval=False
    )
    assert consumed.owner_approved_by is None


def test_consume_requiring_owner_approval_fails_when_unapproved():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="system.upgrade", arguments={}, plan={})
    with pytest.raises(ConfirmationError, match="owner co-signature"):
        store.consume(ticket.confirmation_id, pubkey="abc", tool="system.upgrade", arguments={}, require_owner_approval=True)


def test_ticket_survives_a_failed_owner_approval_check_and_can_be_retried():
    store = ConfirmationStore()
    ticket = store.create(pubkey="abc", tool="system.upgrade", arguments={}, plan={})
    with pytest.raises(ConfirmationError):
        store.consume(ticket.confirmation_id, pubkey="abc", tool="system.upgrade", arguments={}, require_owner_approval=True)
    # Unlike every other failure mode, this one must NOT have consumed the
    # ticket - it's still there, waiting to be approved.
    assert len(store) == 1
    store.approve(ticket.confirmation_id, approver_pubkey="owner", owner_pubkey="owner")
    consumed = store.consume(
        ticket.confirmation_id, pubkey="abc", tool="system.upgrade", arguments={}, require_owner_approval=True
    )
    assert consumed.owner_approved_by == "owner"


def test_approve_then_consume_succeeds():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="backups.restore", arguments={"name": "x"}, plan={})
    store.approve(ticket.confirmation_id, approver_pubkey="owner", owner_pubkey="owner")
    consumed = store.consume(
        ticket.confirmation_id, pubkey="agent", tool="backups.restore", arguments={"name": "x"}, require_owner_approval=True
    )
    assert consumed.owner_approved_by == "owner"


def test_approve_rejects_non_owner_approver():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={}, plan={})
    with pytest.raises(ConfirmationError, match="configured owner"):
        store.approve(ticket.confirmation_id, approver_pubkey="someone-else", owner_pubkey="owner")


def test_approve_allows_same_pubkey_as_requester_when_it_is_the_owner():
    """v1's `solo` profile (owner-approval-plan.md): a human owner calling
    a protected tool directly (no delegated agent) and then approving it
    themselves via a separate NIP-46-signed call is a valid flow - the
    security property is a separate signing act, not a distinct pubkey."""
    store = ConfirmationStore()
    ticket = store.create(pubkey="owner", tool="system.upgrade", arguments={}, plan={})
    approved = store.approve(ticket.confirmation_id, approver_pubkey="owner", owner_pubkey="owner")
    assert approved.owner_approved_by == "owner"


def test_approve_unknown_id_rejected():
    store = ConfirmationStore()
    with pytest.raises(ConfirmationError):
        store.approve("confirm-doesnotexist", approver_pubkey="owner", owner_pubkey="owner")


def test_approve_expired_ticket_rejected():
    store = ConfirmationStore(ttl_seconds=1)
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={}, plan={})
    time.sleep(1.1)
    with pytest.raises(ConfirmationError, match="expired"):
        store.approve(ticket.confirmation_id, approver_pubkey="owner", owner_pubkey="owner")


def test_approve_does_not_consume_the_ticket():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={}, plan={})
    store.approve(ticket.confirmation_id, approver_pubkey="owner", owner_pubkey="owner")
    assert len(store) == 1  # still pending, waiting for the agent's own consume()


# -- owner-approval-plan.md: operation_hash and owner-approval TTL --------


def test_operation_hash_changes_with_arguments():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={"x": 1}, plan={})
    other = store.create(pubkey="agent", tool="system.upgrade", arguments={"x": 2}, plan={})
    assert ticket.operation_hash != other.operation_hash


def test_operation_hash_differs_per_ticket_even_for_identical_requests():
    # Each create() mints a fresh confirmation_id, which the hash binds to
    # - so two otherwise-identical requests still get distinct hashes.
    store = ConfirmationStore()
    a = store.create(pubkey="agent", tool="system.upgrade", arguments={"x": 1}, plan={})
    b = store.create(pubkey="agent", tool="system.upgrade", arguments={"x": 1}, plan={})
    assert a.operation_hash != b.operation_hash


def test_owner_approval_tickets_get_the_longer_ttl():
    store = ConfirmationStore(ttl_seconds=1, owner_approval_ttl_seconds=100)
    ordinary = store.create(pubkey="agent", tool="apps.remove", arguments={}, plan={})
    owner_gated = store.create(
        pubkey="agent", tool="system.upgrade", arguments={}, plan={}, require_owner_signature=True
    )
    assert owner_gated.expires_at - ordinary.expires_at >= 90


def test_owner_approval_ttl_defaults_to_ordinary_ttl_when_not_given():
    store = ConfirmationStore(ttl_seconds=1)
    ordinary = store.create(pubkey="agent", tool="apps.remove", arguments={}, plan={})
    owner_gated = store.create(
        pubkey="agent", tool="system.upgrade", arguments={}, plan={}, require_owner_signature=True
    )
    assert owner_gated.expires_at == pytest.approx(ordinary.expires_at, abs=0.1)
