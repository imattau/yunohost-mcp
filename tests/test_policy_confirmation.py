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
    store.approve(ticket.confirmation_id, approver_pubkey="owner")
    consumed = store.consume(
        ticket.confirmation_id, pubkey="abc", tool="system.upgrade", arguments={}, require_owner_approval=True
    )
    assert consumed.owner_approved_by == "owner"


def test_approve_then_consume_succeeds():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="backups.restore", arguments={"name": "x"}, plan={})
    store.approve(ticket.confirmation_id, approver_pubkey="owner")
    consumed = store.consume(
        ticket.confirmation_id, pubkey="agent", tool="backups.restore", arguments={"name": "x"}, require_owner_approval=True
    )
    assert consumed.owner_approved_by == "owner"


def test_approve_rejects_self_approval():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={}, plan={})
    with pytest.raises(ConfirmationError, match="different identity"):
        store.approve(ticket.confirmation_id, approver_pubkey="agent")


def test_approve_unknown_id_rejected():
    store = ConfirmationStore()
    with pytest.raises(ConfirmationError):
        store.approve("confirm-doesnotexist", approver_pubkey="owner")


def test_approve_expired_ticket_rejected():
    store = ConfirmationStore(ttl_seconds=1)
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={}, plan={})
    time.sleep(1.1)
    with pytest.raises(ConfirmationError, match="expired"):
        store.approve(ticket.confirmation_id, approver_pubkey="owner")


def test_approve_does_not_consume_the_ticket():
    store = ConfirmationStore()
    ticket = store.create(pubkey="agent", tool="system.upgrade", arguments={}, plan={})
    store.approve(ticket.confirmation_id, approver_pubkey="owner")
    assert len(store) == 1  # still pending, waiting for the agent's own consume()
