"""Optional package-announcement workflow for an already-joined identity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from coincurve import PrivateKey, PublicKeyXOnly

from .auth.nostr import NostrEvent, UnsignedNostrEvent, sign_event
from .concord_announcements import AnnouncementDraft, build_announcement_draft, prepare_announcement
from .concord_bundle import ValidatedInviteBundle
from .concord_control import build_roster_authorizer, fold_channel_metadata
from .concord_crypto import self_conversation_encryptor
from .concord_envelope import SealTemplate, build_chat_rumor_and_seal_template, finish_chat_envelope
from .concord_keys import GroupKeyMaterial, derive_group_key
from .concord_transport import RelayPublishResult, publish_signed_event


@dataclass(frozen=True)
class AnnouncementPublishResult:
    status: Literal["published", "no_matching_channel", "ambiguous_channel", "missing_channel_key"]
    draft: AnnouncementDraft
    publication: RelayPublishResult | None = None
    reason: str | None = None


@dataclass(frozen=True)
class PreparedAnnouncementEnvelope:
    """Everything a package announcement needs that requires no author
    secret - the routing decision has already been made, and ``seal_template``
    is the exact event whoever holds ``author_pubkey``'s private key must
    sign to finish it (see ``finish_announcement_envelope``)."""

    rumor: UnsignedNostrEvent
    seal_template: SealTemplate
    stream_key: GroupKeyMaterial
    draft: AnnouncementDraft
    relays: tuple[str, ...]


def prepare_announcement_envelope(
    *,
    source: str,
    catalogue_publication: dict[str, Any],
    bundle: ValidatedInviteBundle,
    control_rumors: list[dict[str, Any]],
    author_pubkey: str,
    created_at: int,
    millisecond: int = 0,
) -> PreparedAnnouncementEnvelope | AnnouncementPublishResult:
    """Route and prepare one package announcement.

    Returns an ``AnnouncementPublishResult`` directly (never raising) for a
    routing outcome that isn't ready to sign - no matching/ambiguous channel,
    or a private channel this invite bundle has no key for - exactly as
    ``publish_package_announcement`` did before this function existed.
    """

    draft = build_announcement_draft(source, catalogue_publication)
    authorize = build_roster_authorizer(control_rumors, owner=bundle.owner)
    channels = fold_channel_metadata(control_rumors, authorize=authorize)
    prepared = prepare_announcement(source, catalogue_publication, channels)
    if prepared.status != "ready":
        return AnnouncementPublishResult(prepared.status, draft, reason=prepared.reason)
    assert prepared.channel is not None
    grant = next((channel for channel in bundle.channels if channel.id == prepared.channel.channel_id), None)
    if prepared.channel.private:
        if grant is None or grant.key is None:
            return AnnouncementPublishResult(
                "missing_channel_key",
                draft,
                reason=f"bot has no key for private channel {prepared.channel.channel_id!r}",
            )
        stream_key = derive_group_key(grant.key, "concord/channel", bytes.fromhex(grant.id), grant.epoch)
    else:
        stream_key = derive_group_key(
            bundle.community_root,
            "concord/channel",
            bytes.fromhex(prepared.channel.channel_id),
            bundle.root_epoch,
        )
    epoch = grant.epoch if prepared.channel.private and grant is not None else bundle.root_epoch
    rumor, seal_template = build_chat_rumor_and_seal_template(
        author_pubkey=author_pubkey,
        stream_key=stream_key,
        channel_id=prepared.channel.channel_id,
        epoch=epoch,
        text=draft.text,
        encrypt=self_conversation_encryptor(stream_key),
        created_at=created_at,
        millisecond=millisecond,
    )
    return PreparedAnnouncementEnvelope(
        rumor=rumor,
        seal_template=seal_template,
        stream_key=stream_key,
        draft=draft,
        relays=tuple(bundle.relays),
    )


async def finish_announcement_envelope(
    *,
    prepared: PreparedAnnouncementEnvelope,
    signed_seal: NostrEvent,
    publisher: Callable[..., Awaitable[RelayPublishResult]] = publish_signed_event,
) -> AnnouncementPublishResult:
    """Complete and publish a prepared announcement once its seal is signed.

    Raises ConcordEnvelopeError (from ``finish_chat_envelope``) if
    ``signed_seal`` does not match the template ``prepared`` was issued
    with, or carries an invalid signature.
    """

    ephemeral = PrivateKey()
    envelope = finish_chat_envelope(
        rumor=prepared.rumor,
        seal_template=prepared.seal_template,
        signed_seal=signed_seal,
        stream_key=prepared.stream_key,
        ephemeral_key=ephemeral,
        encrypt=self_conversation_encryptor(prepared.stream_key),
        created_at=prepared.seal_template.created_at,
    )
    published = await publisher(envelope.wrap, list(prepared.relays))
    return AnnouncementPublishResult("published", prepared.draft, publication=published)


async def publish_package_announcement(
    *,
    source: str,
    catalogue_publication: dict[str, Any],
    bundle: ValidatedInviteBundle,
    control_rumors: list[dict[str, Any]],
    bot_key: PrivateKey,
    created_at: int,
    millisecond: int = 0,
    publisher: Callable[..., Awaitable[RelayPublishResult]] = publish_signed_event,
) -> AnnouncementPublishResult:
    """Publish one optional package announcement to the mapped channel.

    The bot must already be a member and hold the selected channel key. This
    workflow performs no invite acceptance or role escalation. Any routing
    warning is returned as a result so the catalogue operation can remain
    authoritative and successful.

    One-shot convenience over ``prepare_announcement_envelope`` +
    ``finish_announcement_envelope`` for callers that hold ``bot_key``
    directly (the shared bot key path) rather than needing a
    caller-supplied signature.
    """

    author_pubkey = PublicKeyXOnly.from_valid_secret(bot_key.secret).format().hex()
    prepared = prepare_announcement_envelope(
        source=source,
        catalogue_publication=catalogue_publication,
        bundle=bundle,
        control_rumors=control_rumors,
        author_pubkey=author_pubkey,
        created_at=created_at,
        millisecond=millisecond,
    )
    if isinstance(prepared, AnnouncementPublishResult):
        return prepared
    signed_seal = sign_event(
        bot_key,
        pubkey=prepared.seal_template.pubkey,
        kind=prepared.seal_template.kind,
        tags=prepared.seal_template.tags,
        content=prepared.seal_template.content,
        created_at=prepared.seal_template.created_at,
    )
    return await finish_announcement_envelope(prepared=prepared, signed_seal=signed_seal, publisher=publisher)
