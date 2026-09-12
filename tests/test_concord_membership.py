import json

from nostr_sdk import Keys, SecretKey

from yunohost_mcp.auth.nostr import verify_event
from yunohost_mcp.concord_crypto import decrypt_self_conversation
from yunohost_mcp.concord_keys import derive_group_key
from yunohost_mcp.concord_membership import build_join_envelope


def test_build_join_envelope_requires_explicit_event_construction():
    bot = Keys(SecretKey.from_bytes(b"b" * 32))
    community_root = b"r" * 32
    community_id = b"c" * 32
    rumor, seal, wrap = build_join_envelope(
        bot_key=bot,
        community_root=community_root,
        community_id=community_id,
        epoch=0,
        created_at=1_700_000_000,
        invite_creator="a" * 64,
        invite_label="package bot",
    )

    verify_event(seal)
    verify_event(wrap)
    assert rumor.kind == 3306
    assert rumor.content == "join"
    assert rumor.tags == [["ms", "0"], ["invite", "a" * 64, "package bot"]]
    assert "sig" not in rumor.model_dump()

    guestbook = derive_group_key(community_root, "concord/guestbook", community_id, 0)
    decrypted_seal = json.loads(decrypt_self_conversation(guestbook, wrap.content))
    decrypted_rumor = json.loads(decrypt_self_conversation(guestbook, decrypted_seal["content"]))
    assert decrypted_rumor["kind"] == 3306
    assert decrypted_rumor["content"] == "join"
