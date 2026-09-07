import json

from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nostr import verify_event
from yunohost_mcp.concord_envelope import build_chat_envelope
from yunohost_mcp.concord_crypto import decrypt_self_conversation, self_conversation_encryptor
from yunohost_mcp.concord_keys import derive_group_key


def test_build_chat_envelope_has_unsigned_rumor_and_two_signed_layers():
    author = PrivateKey(b"a" * 32)
    ephemeral = PrivateKey(b"e" * 32)
    stream = derive_group_key(b"s" * 32, "concord/channel", b"c" * 32, 0)
    encrypted = []

    def encrypt(value: str) -> str:
        encrypted.append(json.loads(value))
        return f"encrypted-{len(encrypted)}"

    envelope = build_chat_envelope(
        author_key=author,
        stream_key=stream,
        channel_id="channel-id",
        epoch=0,
        text="Package published",
        encrypt=encrypt,
        ephemeral_key=ephemeral,
        created_at=1_700_000_000,
        millisecond=42,
    )

    verify_event(envelope.seal)
    verify_event(envelope.wrap)
    assert envelope.rumor.kind == 9
    assert "sig" not in envelope.rumor.model_dump()
    assert envelope.rumor.tags == [["channel", "channel-id"], ["epoch", "0"], ["ms", "42"]]
    assert envelope.seal.kind == 20013
    assert envelope.wrap.kind == 1059
    assert envelope.wrap.pubkey == stream.pubkey_hex
    ephemeral_pubkey = PublicKeyXOnly.from_valid_secret(ephemeral.secret).format().hex()
    assert envelope.wrap.tags == [["p", ephemeral_pubkey]]
    assert encrypted[0]["kind"] == 9
    assert encrypted[1]["kind"] == 20013


def test_nip44_self_conversation_round_trips_envelope_layers():
    author = PrivateKey(b"a" * 32)
    ephemeral = PrivateKey(b"e" * 32)
    stream = derive_group_key(b"s" * 32, "concord/channel", b"c" * 32, 0)
    encrypt = self_conversation_encryptor(stream)
    envelope = build_chat_envelope(
        author_key=author,
        stream_key=stream,
        channel_id="channel-id",
        epoch=0,
        text="Package published",
        encrypt=encrypt,
        ephemeral_key=ephemeral,
        created_at=1_700_000_000,
    )

    seal = decrypt_self_conversation(stream, envelope.wrap.content)
    rumor = decrypt_self_conversation(stream, json.loads(seal)["content"])
    assert json.loads(seal)["kind"] == 20013
    assert json.loads(rumor)["kind"] == 9
    assert json.loads(rumor)["content"] == "Package published"
