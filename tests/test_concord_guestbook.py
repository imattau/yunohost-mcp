import pytest
from coincurve import PrivateKey

from yunohost_mcp.concord_guestbook import decode_guestbook_wrap, fold_guestbook
from yunohost_mcp.concord_keys import derive_group_key
from yunohost_mcp.concord_membership import build_join_envelope


def test_decode_guestbook_join_wrap():
    root = b"r" * 32
    community = b"c" * 32
    _, _, wrap = build_join_envelope(
        bot_key=PrivateKey(b"b" * 32),
        community_root=root,
        community_id=community,
        epoch=2,
        created_at=1_700_000_000,
        millisecond=123,
    )
    key = derive_group_key(root, "concord/guestbook", community, 2)

    rumor = decode_guestbook_wrap(wrap.model_dump(), key)

    assert rumor["kind"] == 3306
    assert rumor["content"] == "join"
    assert rumor["tags"] == [["ms", "123"]]


def test_fold_guestbook_uses_newest_event_and_rejects_future_or_malformed():
    member = "a" * 64
    older = {"id": "f" * 64, "pubkey": member, "kind": 3306, "content": "join", "created_at": 10, "tags": []}
    newer = {"id": "1" * 64, "pubkey": member, "kind": 3306, "content": "leave", "created_at": 11, "tags": [["ms", "999"]]}
    future = {"id": "0" * 64, "pubkey": "b" * 64, "kind": 3306, "content": "join", "created_at": 100_000, "tags": []}
    malformed = {"id": "2" * 64, "pubkey": member, "kind": 3306, "content": "join", "created_at": 12, "tags": [["ms", "1000"]]}

    states = fold_guestbook([older, newer, future, malformed], now_ms=11_000)

    assert states[member].status == "leave"
    assert "b" * 64 not in states


def test_fold_guestbook_accepts_kick_only_with_authorization():
    member = "a" * 64
    kick = {
        "id": "1" * 64,
        "pubkey": "b" * 64,
        "kind": 3309,
        "content": "",
        "created_at": 11,
        "tags": [["p", member], ["vac", "g", "1", "h"]],
    }
    present = {"id": "2" * 64, "pubkey": member, "kind": 3306, "content": "join", "created_at": 10, "tags": []}

    assert fold_guestbook([present, kick], now_ms=20_000)[member].status == "join"
    states = fold_guestbook([present, kick], now_ms=20_000, authorize_kick=lambda rumor: rumor == kick)
    assert states[member].status == "leave"


def test_fold_guestbook_accepts_authorized_snapshot_and_filters_bans():
    retained = "a" * 64
    banned = "b" * 64
    snapshot = {
        "id": "3" * 64,
        "pubkey": "c" * 64,
        "kind": 3312,
        "content": f'["{retained}","{banned}"]',
        "created_at": 10,
        "tags": [["snap", "s" * 64, "0", "1"]],
    }

    states = fold_guestbook(
        [snapshot],
        now_ms=20_000,
        authorize_snapshot=lambda rumor: rumor == snapshot,
        banned_members=[banned],
    )

    assert set(states) == {retained}
    assert states[retained].status == "join"


@pytest.mark.parametrize("bad_ms", ["x", "1000"])
def test_fold_guestbook_drops_invalid_ms(bad_ms):
    rumor = {"id": "a" * 64, "pubkey": "b" * 64, "kind": 3306, "content": "join", "created_at": 1, "tags": [["ms", bad_ms]]}
    assert fold_guestbook([rumor], now_ms=10_000) == {}
