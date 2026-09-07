"""CORD-01 chat envelope construction.

Only local event construction lives here. The caller supplies the NIP-44
conversation-key encryptor and the ephemeral key used for the outer ``p``
tag, so this module cannot silently choose a relay, load a secret, or publish.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable

from coincurve import PrivateKey, PublicKeyXOnly

from .auth.nostr import NostrEvent, UnsignedNostrEvent, compute_event_id, sign_event
from .concord_keys import GroupKeyMaterial


@dataclass(frozen=True)
class ConcordEnvelope:
    """The three event layers needed for a CORD-01 chat message."""

    rumor: UnsignedNostrEvent
    seal: NostrEvent
    wrap: NostrEvent


def _json(value: NostrEvent | UnsignedNostrEvent) -> str:
    return json.dumps(value.model_dump(), separators=(",", ":"), ensure_ascii=False)


def build_chat_envelope(
    *,
    author_key: PrivateKey,
    stream_key: GroupKeyMaterial,
    channel_id: str,
    epoch: int,
    text: str,
    encrypt: Callable[[str], str],
    ephemeral_key: PrivateKey,
    created_at: int,
    millisecond: int = 0,
) -> ConcordEnvelope:
    """Build a CORD-01 Chat Plane envelope for one kind-9 message.

    ``encrypt`` must implement NIP-44 encryption with the channel stream's
    self-conversation key. It is called exactly twice: rumor into seal and
    seal into wrap. The caller retains ``ephemeral_key`` if it later needs to
    delete the outer wrap.
    """

    if not channel_id:
        raise ValueError("channel_id must not be empty")
    if epoch < 0:
        raise ValueError("epoch must not be negative")
    if not 0 <= millisecond <= 999:
        raise ValueError("millisecond must be between 0 and 999")
    author_pubkey = PublicKeyXOnly.from_valid_secret(author_key.secret).format().hex()
    ephemeral_pubkey = PublicKeyXOnly.from_valid_secret(ephemeral_key.secret).format().hex()
    tags = [["channel", channel_id], ["epoch", str(epoch)], ["ms", str(millisecond)]]
    rumor = UnsignedNostrEvent(
        id="0" * 64,
        pubkey=author_pubkey,
        created_at=created_at,
        kind=9,
        tags=tags,
        content=text,
    )
    rumor = rumor.model_copy(update={"id": compute_event_id(rumor)})
    seal = sign_event(
        author_key,
        pubkey=author_pubkey,
        kind=20013,
        tags=[],
        content=encrypt(_json(rumor)),
        created_at=created_at,
    )
    wrap = sign_event(
        PrivateKey(stream_key.secret),
        pubkey=stream_key.pubkey_hex,
        kind=1059,
        tags=[["p", ephemeral_pubkey]],
        content=encrypt(_json(seal)),
        created_at=created_at,
    )
    return ConcordEnvelope(rumor=rumor, seal=seal, wrap=wrap)
