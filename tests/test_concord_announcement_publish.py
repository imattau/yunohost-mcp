import hashlib

import pytest
from coincurve import PrivateKey

from yunohost_mcp.concord_announcement_publish import publish_package_announcement
from yunohost_mcp.concord_bundle import validate_invite_bundle
from yunohost_mcp.concord_transport import RelayPublishResult


def _bundle():
    owner = "a" * 64
    salt = "b" * 64
    return validate_invite_bundle(
        {
            "community_id": hashlib.sha256(b"concord/community" + bytes.fromhex(owner + salt)).hexdigest(),
            "owner": owner,
            "owner_salt": salt,
            "community_root": "c" * 64,
            "root_epoch": 2,
            "control_pk": "d" * 64,
            "relays": ["wss://relay.example"],
            "channels": [{"id": "e" * 64, "epoch": 1, "name": "ditto_ynh"}],
        }
    )


def _channel_rumor():
    content = '{"name":"ditto_ynh","private":false}'
    channel = "e" * 64
    return {
        "id": "a" * 64,
        "pubkey": "a" * 64,
        "created_at": 1,
        "kind": 3308,
        "tags": [["vsk", "2"], ["eid", channel], ["ev", "1"]],
        "content": content,
    }


@pytest.mark.anyio
async def test_publish_package_announcement_routes_and_publishes():
    published = []

    async def publisher(event, relays):
        published.append((event, relays))
        return RelayPublishResult(event_id=event.id, relays=tuple(relays))

    result = await publish_package_announcement(
        source="https://example.org/ditto_ynh.git",
        catalogue_publication={"app_id": "ditto", "version": "1.2~ynh1", "naddr": "naddr1example"},
        bundle=_bundle(),
        control_rumors=[_channel_rumor()],
        bot_key=PrivateKey(b"b" * 32),
        created_at=1_700_000_000,
        publisher=publisher,
    )

    assert result.status == "published"
    assert len(published) == 1
    assert published[0][1] == ["wss://relay.example"]


@pytest.mark.anyio
async def test_publish_package_announcement_does_not_publish_without_a_channel():
    published = False

    async def publisher(event, relays):
        nonlocal published
        published = True
        return RelayPublishResult(event_id=event.id, relays=tuple(relays))

    result = await publish_package_announcement(
        source="/srv/ditto_ynh",
        catalogue_publication={"app_id": "ditto", "version": "1.2~ynh1"},
        bundle=_bundle(),
        control_rumors=[],
        bot_key=PrivateKey(b"b" * 32),
        created_at=1_700_000_000,
        publisher=publisher,
    )

    assert result.status == "no_matching_channel"
    assert published is False
