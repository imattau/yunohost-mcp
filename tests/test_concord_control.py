import json

from yunohost_mcp.concord_control import build_roster_authorizer, edition_hash, fold_channel_metadata


def _event(channel_id: str, version: int, state: dict, previous: str | None = None, event_id: str = "a" * 64):
    return {
        "id": event_id,
        "kind": 3308,
        "content": json.dumps(state, separators=(",", ":")),
        "tags": [["vsk", "2"], ["eid", channel_id], ["ev", str(version)]],
    } | ({"tags": [["vsk", "2"], ["eid", channel_id], ["ev", str(version)], ["ep", previous]]} if previous else {})


def test_fold_channel_metadata_follows_intact_chain_and_omits_deletion():
    channel = "c" * 64
    first = _event(channel, 1, {"name": "ditto_ynh", "private": False})
    first_hash = edition_hash(channel, 1, None, first["content"])
    second = _event(channel, 2, {"name": "ditto_ynh", "private": False}, first_hash, "b" * 64)
    deleted = _event(channel, 3, {"name": "ditto_ynh", "private": False, "deleted": True}, edition_hash(channel, 2, first_hash, second["content"]), "c" * 64)

    assert fold_channel_metadata([deleted, second, first]) == []


def test_fold_channel_metadata_uses_lowest_event_id_for_same_version():
    channel = "d" * 64
    first = _event(channel, 1, {"name": "old", "private": False})
    first_hash = edition_hash(channel, 1, None, first["content"])
    high = _event(channel, 2, {"name": "ditto_ynh", "private": False}, first_hash, "f" * 64)
    low = _event(channel, 2, {"name": "wrong", "private": True}, first_hash, "e" * 64)

    folded = fold_channel_metadata([high, low, first])
    assert folded[0]["name"] == "wrong"
    assert folded[0]["private"] is True


def test_fold_channel_metadata_rejects_broken_chain_and_malformed_events():
    channel = "e" * 64
    broken = _event(channel, 2, {"name": "ditto_ynh", "private": False}, "0" * 64)
    malformed = {"kind": 3308, "tags": [["vsk", "2"]], "content": "{}"}

    assert fold_channel_metadata([broken, malformed]) == []


def test_fold_channel_metadata_can_require_caller_authorization():
    channel = "f" * 64
    authorized = _event(channel, 1, {"name": "ditto_ynh", "private": False}) | {"pubkey": "owner"}
    unauthorized = _event("0" * 64, 1, {"name": "other", "private": False}, event_id="b" * 64) | {"pubkey": "stranger"}

    folded = fold_channel_metadata([authorized, unauthorized], authorize=lambda event: event.get("pubkey") == "owner")

    assert len(folded) == 1
    assert folded[0]["name"] == "ditto_ynh"


def test_roster_authorizer_accepts_owner_and_granted_channel_manager():
    owner = "1" * 64
    member = "2" * 64
    role_id = "3" * 64
    grant_id = "4" * 64
    channel = "5" * 64
    role_content = json.dumps(
        {"role_id": role_id, "name": "channel manager", "position": 10, "permissions": str(1 << 1)},
        separators=(",", ":"),
    )
    role = {
        "id": "a" * 64,
        "pubkey": owner,
        "kind": 3308,
        "content": role_content,
        "tags": [["vsk", "1"], ["eid", role_id], ["ev", "1"]],
    }
    grant_content = json.dumps({"member": member, "role_ids": [role_id]}, separators=(",", ":"))
    grant = {
        "id": "b" * 64,
        "pubkey": owner,
        "kind": 3308,
        "content": grant_content,
        "tags": [["vsk", "3"], ["eid", grant_id], ["ev", "1"]],
    }
    grant_digest = edition_hash(grant_id, 1, None, grant_content)
    channel_content = '{"name":"ditto_ynh","private":false}'
    channel = {
        "id": "c" * 64,
        "pubkey": member,
        "kind": 3308,
        "content": channel_content,
        "tags": [["vsk", "2"], ["eid", channel], ["ev", "1"], ["vac", grant_id, "1", grant_digest]],
    }

    authorize = build_roster_authorizer([role, grant, channel], owner=owner)

    assert authorize(channel)
    assert fold_channel_metadata([channel], authorize=authorize)[0]["name"] == "ditto_ynh"


def test_roster_authorizer_rejects_unrostered_channel_edits_and_bad_vac():
    owner = "6" * 64
    channel = "7" * 64
    event = _event(channel, 1, {"name": "ditto_ynh", "private": False}) | {"pubkey": "8" * 64}
    authorize = build_roster_authorizer([event], owner=owner)

    assert not authorize(event)
    assert fold_channel_metadata([event], authorize=authorize) == []
