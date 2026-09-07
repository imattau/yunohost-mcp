import hashlib
import json

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.concord_bundle import validate_invite_bundle
from yunohost_mcp.concord_control_reader import load_control_rumors
from yunohost_mcp.concord_crypto import self_conversation_encryptor
from yunohost_mcp.concord_keys import derive_group_key


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
    signer = PrivateKey(b"k" * 32)
    signer_pubkey = PublicKeyXOnly.from_valid_secret(signer.secret).format().hex()
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
