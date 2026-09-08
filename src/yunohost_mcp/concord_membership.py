"""Explicit Concord membership event construction for a bot identity.

Like ``concord_envelope.py``, the guestbook join envelope only needs the
author's private key for one Schnorr signature (the seal layer) - the wrap
layer is signed by the shared guestbook key, and encryption is self-ECDH on
that same shared key. ``build_join_rumor_and_seal_template``/
``finish_join_envelope`` split ``build_join_envelope`` at exactly that
signature, for a caller (an MCP agent) that must sign with its own
client-held key instead of a key held here.
"""

from __future__ import annotations

from coincurve import PrivateKey, PublicKeyXOnly

from .auth.nostr import NostrEvent, UnsignedNostrEvent, compute_event_id, sign_event, verify_event
from .concord_crypto import self_conversation_encryptor
from .concord_envelope import ConcordEnvelopeError, SealTemplate
from .concord_keys import GroupKeyMaterial, derive_group_key


def build_join_rumor_and_seal_template(
    *,
    bot_pubkey: str,
    community_root: bytes,
    community_id: bytes,
    epoch: int,
    created_at: int,
    millisecond: int = 0,
    invite_creator: str | None = None,
    invite_label: str | None = None,
) -> tuple[UnsignedNostrEvent, SealTemplate, GroupKeyMaterial]:
    """Build everything for a CORD-02 Guestbook join that needs no author
    secret: the plaintext rumor, the exact seal event whoever holds
    ``bot_pubkey``'s private key must sign to complete it, and the derived
    guestbook key ``finish_join_envelope`` needs to build the wrap layer."""

    if len(community_root) != 32 or len(community_id) != 32:
        raise ValueError("community_root and community_id must be 32 bytes")
    if epoch < 0 or not 0 <= millisecond <= 999:
        raise ValueError("invalid epoch or millisecond")
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
    seal_template = SealTemplate(
        pubkey=bot_pubkey,
        kind=20013,
        tags=[],
        content=encrypt(rumor.model_dump_json()),
        created_at=created_at,
    )
    return rumor, seal_template, guestbook_key


def finish_join_envelope(
    *,
    rumor: UnsignedNostrEvent,
    seal_template: SealTemplate,
    signed_seal: NostrEvent,
    guestbook_key: GroupKeyMaterial,
    created_at: int,
) -> tuple[UnsignedNostrEvent, NostrEvent, NostrEvent]:
    """Complete a split join envelope once the author has signed
    ``seal_template``.

    Raises ConcordEnvelopeError if ``signed_seal`` drifted from the
    template it was issued against, or carries an invalid signature.
    """

    if not seal_template.matches(signed_seal):
        raise ConcordEnvelopeError("signed seal does not match the issued template")
    verify_event(signed_seal)
    encrypt = self_conversation_encryptor(guestbook_key)
    ephemeral = PrivateKey()
    wrap = sign_event(
        PrivateKey(guestbook_key.secret),
        pubkey=guestbook_key.pubkey_hex,
        kind=1059,
        tags=[["p", PublicKeyXOnly.from_valid_secret(ephemeral.secret).format().hex()]],
        content=encrypt(signed_seal.model_dump_json()),
        created_at=created_at,
    )
    return rumor, signed_seal, wrap


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

    One-shot convenience over ``build_join_rumor_and_seal_template`` +
    ``finish_join_envelope`` for callers that hold ``bot_key`` directly (the
    shared bot key path) rather than needing a caller-supplied signature.
    """

    bot_pubkey = PublicKeyXOnly.from_valid_secret(bot_key.secret).format().hex()
    rumor, seal_template, guestbook_key = build_join_rumor_and_seal_template(
        bot_pubkey=bot_pubkey,
        community_root=community_root,
        community_id=community_id,
        epoch=epoch,
        created_at=created_at,
        millisecond=millisecond,
        invite_creator=invite_creator,
        invite_label=invite_label,
    )
    signed_seal = sign_event(
        bot_key,
        pubkey=seal_template.pubkey,
        kind=seal_template.kind,
        tags=seal_template.tags,
        content=seal_template.content,
        created_at=seal_template.created_at,
    )
    return finish_join_envelope(
        rumor=rumor,
        seal_template=seal_template,
        signed_seal=signed_seal,
        guestbook_key=guestbook_key,
        created_at=created_at,
    )
