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
