import hashlib
import json

import pytest
from nostr_sdk import Keys, SecretKey

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.concord_bundle import validate_invite_bundle
from yunohost_mcp.concord_control_reader import load_control_rumors
from yunohost_mcp.concord_crypto import self_conversation_encryptor
from yunohost_mcp.concord_keys import derive_group_key
from yunohost_mcp.concord_transport import fetch_control_events


def _bundle(control_pk):
    owner = "a" * 64
    salt = "b" * 64
    return validate_invite_bundle(
        {
            "community_id": hashlib.sha256(b"concord/community" + bytes.fromhex(owner + salt)).hexdigest(),
            "owner": owner,
            "owner_salt": salt,
            "community_root": "c" * 64,
            "root_epoch": 2,
            "control_pk": control_pk,
            "relays": ["wss://relay.example"],
            "channels": [],
        }
    )


@pytest.mark.anyio
async def test_load_control_rumors_derives_read_key_and_decodes_wrap():
    root = bytes.fromhex("c" * 64)
    community_id = bytes.fromhex(
        hashlib.sha256(
            b"concord/community" + bytes.fromhex("a" * 64 + "b" * 64)
        ).hexdigest()
    )
    read_key = derive_group_key(root, "concord/control", community_id, 2)
    signer = Keys(SecretKey.from_bytes(b"k" * 32))
    signer_pubkey = signer.public_key().to_hex()
    rumor = {
        "id": "0" * 64,
        "pubkey": signer_pubkey,
        "created_at": 1,
        "kind": 3308,
        "tags": [["vsk", "2"], ["eid", "e" * 64], ["ev", "1"]],
        "content": '{"name":"ditto_ynh","private":false}',
    }
    from yunohost_mcp.auth.nostr import UnsignedNostrEvent, compute_event_id

    rumor["id"] = compute_event_id(UnsignedNostrEvent.model_validate(rumor))
    seal = sign_event(signer, pubkey=signer_pubkey, kind=20014, tags=[], content=json.dumps(rumor, separators=(",", ":")), created_at=1)
    wrap = sign_event(
        signer,
        pubkey=signer_pubkey,
        kind=1059,
        tags=[["p", "f" * 64]],
        content=self_conversation_encryptor(read_key)(seal.model_dump_json()),
        created_at=1,
    )

    async def fetcher(stream, relays):
        assert stream == signer_pubkey
        assert relays == ["wss://relay.example"]
        return [wrap]

    rumors = await load_control_rumors(_bundle(signer_pubkey), fetcher=fetcher)

    assert rumors[0]["kind"] == 3308


@pytest.mark.anyio
async def test_fetch_control_events_fetches_relays_independently_and_deduplicates():
    calls = []

    class FakeClient:
        def __init__(self):
            self.relays = []

        async def add_relay(self, relay):
            self.relays.append(str(relay))

        async def connect(self):
            return None

        async def fetch_events(self, _request, *, timeout, max_events):
            assert max_events == 3
            calls.append(tuple(self.relays))
            # This fake deliberately rejects multi-relay clients, matching the
            # SDK failure seen in production when aggregate results exceed the
            # requested max_events.
            assert len(self.relays) == 1
            relay_index = len(calls)
            return [
                {"id": "shared"},
                {"id": f"event-{relay_index}"},
            ]

        async def shutdown(self):
            return None

    events = await fetch_control_events(
        "11" * 32,
        ["wss://one.example", "wss://two.example"],
        max_events=3,
        client_factory=FakeClient,
    )

    assert calls == [("wss://one.example",), ("wss://two.example",)]
    assert [event["id"] for event in events] == ["shared", "event-1", "event-2"]


@pytest.mark.anyio
async def test_fetch_control_events_normalizes_all_relay_failures():
    class FailingClient:
        async def add_relay(self, _relay):
            return None

        async def connect(self):
            return None

        async def fetch_events(self, _request, *, timeout, max_events):
            raise RuntimeError("too many fetched events")

        async def shutdown(self):
            return None

    with pytest.raises(ValueError, match="unable to fetch Concord control events"):
        await fetch_control_events(
            "11" * 32,
            ["wss://one.example", "wss://two.example"],
            client_factory=FailingClient,
        )
