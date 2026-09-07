"""Explicit Concord membership event construction for a bot identity."""

from __future__ import annotations

from coincurve import PrivateKey, PublicKeyXOnly

from .auth.nostr import NostrEvent, UnsignedNostrEvent, compute_event_id, sign_event
from .concord_crypto import self_conversation_encryptor
from .concord_keys import GroupKeyMaterial, derive_group_key


def build_join_envelope(
    *,
    bot_key: PrivateKey,
    community_root: bytes,
    community_id: bytes,
    epoch: int,
    created_at: int,
    millisecond: int = 0,
    invite_creator: str | None = None,
    invite_label: str | None = None,
) -> tuple[UnsignedNostrEvent, NostrEvent, NostrEvent]:
    """Build a signed CORD-02 Guestbook ``join`` envelope.

    This function only builds the event. The caller must require explicit
    acceptance before publishing it; loading or previewing an invite is not
    membership acceptance.
    """

    if len(community_root) != 32 or len(community_id) != 32:
        raise ValueError("community_root and community_id must be 32 bytes")
    if epoch < 0 or not 0 <= millisecond <= 999:
        raise ValueError("invalid epoch or millisecond")
    bot_pubkey = PublicKeyXOnly.from_valid_secret(bot_key.secret).format().hex()
    tags = [["ms", str(millisecond)]]
    if invite_creator is not None:
        if len(invite_creator) != 64:
            raise ValueError("invite creator must be 32-byte hex")
        tags.append(["invite", invite_creator, invite_label or ""])
    rumor = UnsignedNostrEvent(
        id="0" * 64,
        pubkey=bot_pubkey,
        created_at=created_at,
        kind=3306,
        tags=tags,
        content="join",
    )
    rumor = rumor.model_copy(update={"id": compute_event_id(rumor)})
    guestbook_key: GroupKeyMaterial = derive_group_key(
        community_root,
        "concord/guestbook",
        community_id,
        epoch,
    )
    encrypt = self_conversation_encryptor(guestbook_key)
    seal = sign_event(
        bot_key,
        pubkey=bot_pubkey,
        kind=20013,
        tags=[],
        content=encrypt(rumor.model_dump_json()),
        created_at=created_at,
    )
    ephemeral = PrivateKey()
    wrap = sign_event(
        PrivateKey(guestbook_key.secret),
        pubkey=guestbook_key.pubkey_hex,
        kind=1059,
        tags=[["p", PublicKeyXOnly.from_valid_secret(ephemeral.secret).format().hex()]],
        content=encrypt(seal.model_dump_json()),
        created_at=created_at,
    )
    return rumor, seal, wrap
