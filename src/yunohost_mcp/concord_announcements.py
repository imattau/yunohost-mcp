"""Pure data preparation for optional Concord/Armada announcements.

This module deliberately does not know how to authenticate to Concord, fetch
community state, or publish encrypted Nostr events.  Keeping the draft
deterministic makes the eventual network writer retryable and keeps catalogue
publication authoritative when chat delivery is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Literal

from .concord_routing import (
    AmbiguousChannelError,
    ChannelMatch,
    match_source_channel,
    normalize_channel_list,
    repository_name,
)


@dataclass(frozen=True)
class AnnouncementDraft:
    """The stable, human-readable payload handed to a Concord writer."""

    idempotency_key: str
    repository_name: str
    app_id: str | None
    version: str | None
    catalogue_reference: str | None
    text: str


@dataclass(frozen=True)
class AnnouncementPreparation:
    """Non-blocking routing result for a post-publication announcement."""

    draft: AnnouncementDraft
    channel: ChannelMatch | None
    status: Literal["ready", "no_matching_channel", "ambiguous_channel"]
    reason: str | None = None


def _event_value(result: dict[str, Any], name: str) -> str | None:
    event = result.get("event")
    if not isinstance(event, dict):
        return None
    for tag in event.get("tags", []):
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == name:
            value = tag[1]
            return value if isinstance(value, str) and value else None
    return None


def build_announcement_draft(
    source: str,
    publication: dict[str, Any],
) -> AnnouncementDraft:
    """Build a retry-safe draft from a successful catalogue publication.

    The catalogue naddr is preferred as the public reference.  Event tags are
    used as a fallback because fake/test results and older CLI versions may
    expose package metadata only there.
    """

    repo = repository_name(source)
    app_id = publication.get("app_id") or _event_value(publication, "d")
    version = publication.get("version") or _event_value(publication, "version")
    naddr = publication.get("naddr")
    if not isinstance(naddr, str) or not naddr:
        naddr = None
    event = publication.get("event")
    event_id = event.get("id") if isinstance(event, dict) else None
    identity = event_id or naddr or f"{repo}:{app_id or ''}:{version or ''}"
    digest = hashlib.sha256(f"{repo}\0{identity}".encode()).hexdigest()[:32]
    package = " ".join(part for part in (app_id, version) if isinstance(part, str) and part)
    text = f"Published {package or repo} to the YunoHost catalogue"
    if naddr:
        text += f": {naddr}"
    return AnnouncementDraft(
        idempotency_key=f"catalogue:{digest}",
        repository_name=repo,
        app_id=app_id if isinstance(app_id, str) else None,
        version=version if isinstance(version, str) else None,
        catalogue_reference=naddr,
        text=text,
    )


def prepare_announcement(
    source: str,
    publication: dict[str, Any],
    channel_payload: Any,
    *,
    aliases: dict[str, str] | None = None,
) -> AnnouncementPreparation:
    """Prepare routing after publication without contacting a relay.

    No matching or ambiguous channel is a reportable announcement warning,
    never a catalogue-publication failure.  The caller can persist the draft
    and retry once community state or an explicit alias is corrected.
    """

    draft = build_announcement_draft(source, publication)
    try:
        channel = match_source_channel(
            source,
            normalize_channel_list(channel_payload),
            aliases=aliases,
        )
    except AmbiguousChannelError as exc:
        return AnnouncementPreparation(draft, None, "ambiguous_channel", str(exc))
    if channel is None:
        return AnnouncementPreparation(
            draft,
            None,
            "no_matching_channel",
            f"no active Concord channel matches repository {draft.repository_name!r}",
        )
    return AnnouncementPreparation(draft, channel, "ready")
