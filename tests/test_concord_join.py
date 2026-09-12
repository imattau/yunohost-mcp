import hashlib

import pytest
from nostr_sdk import Keys, SecretKey

from yunohost_mcp.concord_bundle import validate_invite_bundle
from yunohost_mcp.concord_join import publish_join
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
            "channels": [],
        }
    )


@pytest.mark.anyio
async def test_publish_join_publishes_only_the_join_wrap():
    published = []

    async def publisher(event, relays):
        published.append((event, relays))
        return RelayPublishResult(event_id=event.id, relays=tuple(relays))

    async def fetcher(_pubkey, _relays):
        return [published[0][0].model_dump()]

    result = await publish_join(
        bundle=_bundle(),
        bot_key=Keys(SecretKey.from_bytes(b"e" * 32)),
        created_at=1_700_000_000,
        publisher=publisher,
        fetcher=fetcher,
    )

    assert result.status == "published"
    assert result.verified is True
    assert result.community_id == _bundle().community_id
    assert len(published) == 1
    assert published[0][0].kind == 1059
    assert published[0][1] == ["wss://relay.example"]
