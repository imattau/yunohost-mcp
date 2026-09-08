from __future__ import annotations

from pathlib import Path

import pytest

from yunohost_mcp.concord_pending_signature import PendingSignatureError, PendingSignatureStore


def _store(tmp_path: Path) -> PendingSignatureStore:
    return PendingSignatureStore(tmp_path / "pending.sqlite", ttl_seconds=60)


def test_create_then_consume_round_trips(tmp_path: Path):
    store = _store(tmp_path)
    created = store.create(
        pubkey="agent-a",
        purpose="catalog_announce",
        rumor={"id": "r"},
        seal_template={"pubkey": "agent-a", "kind": 20013},
        stream_key={"secret_hex": "aa", "pubkey_hex": "bb"},
        context={"relays": ["wss://relay.test"]},
    )
    consumed = store.consume(created.draft_id, pubkey="agent-a", purpose="catalog_announce")
    assert consumed.rumor == {"id": "r"}
    assert consumed.context == {"relays": ["wss://relay.test"]}


def test_consume_is_single_use(tmp_path: Path):
    store = _store(tmp_path)
    created = store.create(
        pubkey="agent-a", purpose="armada_join", rumor={}, seal_template={}, stream_key={},
    )
    store.consume(created.draft_id, pubkey="agent-a", purpose="armada_join")
    with pytest.raises(PendingSignatureError):
        store.consume(created.draft_id, pubkey="agent-a", purpose="armada_join")


def test_consume_rejects_a_different_pubkey(tmp_path: Path):
    store = _store(tmp_path)
    created = store.create(
        pubkey="agent-a", purpose="armada_join", rumor={}, seal_template={}, stream_key={},
    )
    with pytest.raises(PendingSignatureError):
        store.consume(created.draft_id, pubkey="agent-b", purpose="armada_join")


def test_consume_rejects_a_different_purpose(tmp_path: Path):
    store = _store(tmp_path)
    created = store.create(
        pubkey="agent-a", purpose="armada_join", rumor={}, seal_template={}, stream_key={},
    )
    with pytest.raises(PendingSignatureError):
        store.consume(created.draft_id, pubkey="agent-a", purpose="catalog_announce")


def test_consume_rejects_an_expired_draft(tmp_path: Path):
    store = PendingSignatureStore(tmp_path / "pending.sqlite", ttl_seconds=0)
    created = store.create(
        pubkey="agent-a", purpose="armada_join", rumor={}, seal_template={}, stream_key={},
    )
    with pytest.raises(PendingSignatureError):
        store.consume(created.draft_id, pubkey="agent-a", purpose="armada_join")


def test_consume_rejects_an_unknown_draft(tmp_path: Path):
    store = _store(tmp_path)
    with pytest.raises(PendingSignatureError):
        store.consume("does-not-exist", pubkey="agent-a", purpose="armada_join")
