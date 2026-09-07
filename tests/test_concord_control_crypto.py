import json

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nostr import UnsignedNostrEvent, compute_event_id, sign_event
from yunohost_mcp.concord_control_crypto import ControlPlaneError, decode_control_wrap
from yunohost_mcp.concord_crypto import decrypt_self_conversation, self_conversation_encryptor
from yunohost_mcp.concord_keys import derive_group_key


def _control_wrap(read_key, control_key, rumor):
    author_pubkey = PublicKeyXOnly.from_valid_secret(control_key.secret).format().hex()
    seal = sign_event(
        control_key,
        pubkey=author_pubkey,
        kind=20014,
        tags=[],
        content=json.dumps(rumor, separators=(",", ":")),
        created_at=1,
    )
    stream_pubkey = PublicKeyXOnly.from_valid_secret(control_key.secret).format().hex()
    return sign_event(
        control_key,
        pubkey=stream_pubkey,
        kind=1059,
        tags=[["p", "f" * 64]],
        content=self_conversation_encryptor(read_key)(seal.model_dump_json()),
        created_at=1,
    )


def test_decode_control_wrap_verifies_seal_and_rumor_binding():
    read_key = derive_group_key(b"r" * 32, "concord/control", b"c" * 32, 0)
    control_key = PrivateKey(b"k" * 32)
    author_pubkey = PublicKeyXOnly.from_valid_secret(control_key.secret).format().hex()
    rumor = {
        "id": "0" * 64,
        "pubkey": author_pubkey,
        "created_at": 1,
        "kind": 3308,
        "tags": [["vsk", "2"], ["eid", "a" * 64], ["ev", "1"]],
        "content": '{"name":"ditto_ynh","private":false}',
    }
    unsigned = UnsignedNostrEvent.model_validate(rumor)
    rumor["id"] = compute_event_id(unsigned)
    wrap = _control_wrap(read_key, control_key, rumor)
    decoded = decode_control_wrap(
        wrap.model_dump(),
        read_key,
        expected_stream_pubkey=wrap.pubkey,
        decrypt=lambda payload: decrypt_self_conversation(read_key, payload),
    )

    assert decoded["kind"] == 3308
    assert decoded["pubkey"] == author_pubkey


def test_decode_control_wrap_rejects_wrong_stream():
    read_key = derive_group_key(b"r" * 32, "concord/control", b"c" * 32, 0)
    key = PrivateKey(b"k" * 32)
    rumor = {"id": "0" * 64, "pubkey": "0" * 64, "created_at": 1, "kind": 3308, "tags": [], "content": "{}"}
    wrap = _control_wrap(read_key, key, rumor)

    with pytest.raises(ControlPlaneError, match="stream"):
        decode_control_wrap(wrap.model_dump(), read_key, expected_stream_pubkey="0" * 64, decrypt=lambda _: "")
