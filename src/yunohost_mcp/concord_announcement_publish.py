"""Optional package-announcement workflow for an already-joined bot."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from coincurve import PrivateKey

from .concord_announcements import AnnouncementDraft, build_announcement_draft, prepare_announcement
from .concord_bundle import ValidatedInviteBundle
from .concord_control import build_roster_authorizer, fold_channel_metadata
from .concord_crypto import self_conversation_encryptor
from .concord_envelope import build_chat_envelope
from .concord_keys import derive_group_key
from .concord_transport import RelayPublishResult, publish_signed_event


@dataclass(frozen=True)
class AnnouncementPublishResult:
    status: Literal["published", "no_matching_channel", "ambiguous_channel", "missing_channel_key"]
    draft: AnnouncementDraft
    publication: RelayPublishResult | None = None
    reason: str | None = None


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
    ephemeral = PrivateKey()
    envelope = build_chat_envelope(
        author_key=bot_key,
        stream_key=stream_key,
        channel_id=prepared.channel.channel_id,
        epoch=grant.epoch if prepared.channel.private and grant is not None else bundle.root_epoch,
        text=draft.text,
        encrypt=self_conversation_encryptor(stream_key),
        ephemeral_key=ephemeral,
        created_at=created_at,
        millisecond=millisecond,
    )
    published = await publisher(envelope.wrap, list(bundle.relays))
    return AnnouncementPublishResult("published", draft, publication=published)
