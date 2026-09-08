"""CORD-01 chat envelope construction.

Only local event construction lives here. The caller supplies the NIP-44
conversation-key encryptor and the ephemeral key used for the outer ``p``
tag, so this module cannot silently choose a relay, load a secret, or publish.

``build_chat_envelope`` needs the author's private key only to produce one
ordinary Schnorr signature (the seal layer) - the wrap layer is signed by
the shared stream key, and NIP-44 encryption here is self-ECDH on that same
shared key, needing no secret from the author at all. ``build_chat_rumor_and_seal_template``/
``finish_chat_envelope`` split the function at exactly that signature, so a
caller who cannot hold the author's private key server-side (an MCP agent
signing with its own client-held key) can complete the envelope by signing
just the returned template and handing the result back.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable

from coincurve import PrivateKey, PublicKeyXOnly

from .auth.nostr import NostrEvent, UnsignedNostrEvent, compute_event_id, sign_event, verify_event
from .concord_keys import GroupKeyMaterial


class ConcordEnvelopeError(ValueError):
    """A signed seal does not match the template it was issued against."""


@dataclass(frozen=True)
class ConcordEnvelope:
    """The three event layers needed for a CORD-01 chat message."""

    rumor: UnsignedNostrEvent
    seal: NostrEvent
    wrap: NostrEvent


@dataclass(frozen=True)
class SealTemplate:
    """The exact unsigned seal event a caller must sign, unchanged, to
    finish a split envelope. Every field is checked against what the
    caller returns - a caller may only sign this content, never substitute
    different content while keeping the same draft id."""

    pubkey: str
    kind: int
    tags: list[list[str]]
    content: str
    created_at: int

    def matches(self, event: NostrEvent) -> bool:
        return (
            event.pubkey == self.pubkey
            and event.kind == self.kind
            and event.tags == self.tags
            and event.content == self.content
            and event.created_at == self.created_at
        )


def _json(value: NostrEvent | UnsignedNostrEvent) -> str:
    return json.dumps(value.model_dump(), separators=(",", ":"), ensure_ascii=False)


def build_chat_rumor_and_seal_template(
    *,
    author_pubkey: str,
    stream_key: GroupKeyMaterial,
    channel_id: str,
    epoch: int,
    text: str,
    encrypt: Callable[[str], str],
    created_at: int,
    millisecond: int = 0,
) -> tuple[UnsignedNostrEvent, SealTemplate]:
    """Build everything for a CORD-01 chat message that needs no author
    secret: the plaintext rumor and the exact seal event someone holding
    ``author_pubkey``'s private key must sign to complete it."""

    if not channel_id:
        raise ValueError("channel_id must not be empty")
    if epoch < 0:
        raise ValueError("epoch must not be negative")
    if not 0 <= millisecond <= 999:
        raise ValueError("millisecond must be between 0 and 999")
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
    seal_template = SealTemplate(
        pubkey=author_pubkey,
        kind=20013,
        tags=[],
        content=encrypt(_json(rumor)),
        created_at=created_at,
    )
    return rumor, seal_template


def finish_chat_envelope(
    *,
    rumor: UnsignedNostrEvent,
    seal_template: SealTemplate,
    signed_seal: NostrEvent,
    stream_key: GroupKeyMaterial,
    ephemeral_key: PrivateKey,
    encrypt: Callable[[str], str],
    created_at: int,
) -> ConcordEnvelope:
    """Complete a split envelope once the author has signed ``seal_template``.

    Raises ConcordEnvelopeError if ``signed_seal`` drifted from the template
    it was issued against, or carries an invalid signature.
    """

    if not seal_template.matches(signed_seal):
        raise ConcordEnvelopeError("signed seal does not match the issued template")
    verify_event(signed_seal)
    ephemeral_pubkey = PublicKeyXOnly.from_valid_secret(ephemeral_key.secret).format().hex()
    wrap = sign_event(
        PrivateKey(stream_key.secret),
        pubkey=stream_key.pubkey_hex,
        kind=1059,
        tags=[["p", ephemeral_pubkey]],
        content=encrypt(_json(signed_seal)),
        created_at=created_at,
    )
    return ConcordEnvelope(rumor=rumor, seal=signed_seal, wrap=wrap)


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

    One-shot convenience over ``build_chat_rumor_and_seal_template`` +
    ``finish_chat_envelope`` for callers that hold ``author_key`` directly
    (the shared bot key path) rather than needing a caller-supplied
    signature.
    """

    author_pubkey = PublicKeyXOnly.from_valid_secret(author_key.secret).format().hex()
    rumor, seal_template = build_chat_rumor_and_seal_template(
        author_pubkey=author_pubkey,
        stream_key=stream_key,
        channel_id=channel_id,
        epoch=epoch,
        text=text,
        encrypt=encrypt,
        created_at=created_at,
        millisecond=millisecond,
    )
    signed_seal = sign_event(
        author_key,
        pubkey=seal_template.pubkey,
        kind=seal_template.kind,
        tags=seal_template.tags,
        content=seal_template.content,
        created_at=seal_template.created_at,
    )
    return finish_chat_envelope(
        rumor=rumor,
        seal_template=seal_template,
        signed_seal=signed_seal,
        stream_key=stream_key,
        ephemeral_key=ephemeral_key,
        encrypt=encrypt,
        created_at=created_at,
    )
