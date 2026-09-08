"""Explicit Concord invite acceptance for an already-authorized bot."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Awaitable, Callable, Literal

from coincurve import PrivateKey, PublicKeyXOnly

from .concord_bundle import ValidatedInviteBundle
from .concord_guestbook import GuestbookError, decode_guestbook_wrap, fold_guestbook
from .concord_membership import build_join_envelope
from .concord_keys import GroupKeyMaterial, derive_group_key
from .concord_transport import RelayPublishResult, fetch_guestbook_events, publish_signed_event


@dataclass(frozen=True)
class JoinPublishResult:
    status: Literal["published", "published_unverified"]
    community_id: str
    publication: RelayPublishResult
    verified: bool


async def publish_join(
    *,
    bundle: ValidatedInviteBundle,
    bot_key: PrivateKey,
    created_at: int,
    millisecond: int = 0,
    publisher: Callable[..., Awaitable[RelayPublishResult]] = publish_signed_event,
    fetcher: Callable[[str, list[str]], Awaitable[list[Any]]] = fetch_guestbook_events,
) -> JoinPublishResult:
    """Publish the bot's self-signed Guestbook Join for one invite bundle."""

    _, _, wrap = build_join_envelope(
        bot_key=bot_key,
        community_root=bundle.community_root,
        community_id=bytes.fromhex(bundle.community_id),
        epoch=bundle.root_epoch,
        created_at=created_at,
        millisecond=millisecond,
    )
    publication = await publisher(wrap, list(bundle.relays))
    bot_pubkey = PublicKeyXOnly.from_valid_secret(bot_key.secret).format().hex()
    guestbook_key = derive_group_key(
        bundle.community_root,
        "concord/guestbook",
        bytes.fromhex(bundle.community_id),
        bundle.root_epoch,
    )
    return await verify_join_publication(
        guestbook_key=guestbook_key,
        community_id=bundle.community_id,
        relays=list(bundle.relays),
        author_pubkey=bot_pubkey,
        publication=publication,
        fetcher=fetcher,
    )


async def verify_join_publication(
    *,
    guestbook_key: GroupKeyMaterial,
    community_id: str,
    relays: list[str],
    author_pubkey: str,
    publication: RelayPublishResult,
    fetcher: Callable[[str, list[str]], Awaitable[list[Any]]] = fetch_guestbook_events,
) -> JoinPublishResult:
    """Best-effort post-publish check that a join is visible in the roster.

    Takes the already-derived guestbook key rather than a full invite
    bundle, so a caller who built and published the wrap independently
    (e.g. from a caller-signed split envelope, see
    ``concord_membership.build_join_rumor_and_seal_template`` - which
    already derives and needs this same key) gets the same verification
    without re-deriving anything or needing the private key ``publish_join``
    uses to derive its own author pubkey.
    """
    try:
        events = await fetcher(guestbook_key.pubkey_hex, relays)
    except Exception:  # noqa: BLE001 - verification is best-effort after publish
        return JoinPublishResult("published_unverified", community_id, publication, False)
    exact_event_seen = any(_event_id(event) == publication.event_id for event in events)
    rumors = []
    for event in events:
        if not isinstance(event, dict) and hasattr(event, "as_json"):
            try:
                event = json.loads(event.as_json())
            except (TypeError, ValueError):
                continue
        if not isinstance(event, dict):
            continue
        try:
            rumors.append(decode_guestbook_wrap(event, guestbook_key))
        except GuestbookError:
            continue
    current = fold_guestbook(rumors).get(author_pubkey)
    verified = exact_event_seen and current is not None and current.status == "join"
    return JoinPublishResult(
        "published" if verified else "published_unverified",
        community_id,
        publication,
        verified,
    )


def _event_id(event: Any) -> str | None:
    if isinstance(event, dict):
        value = event.get("id")
        return value if isinstance(value, str) else None
    if hasattr(event, "as_json"):
        try:
            value = json.loads(event.as_json()).get("id")
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, str) else None
    if hasattr(event, "id"):
        value = event.id()
        return value if isinstance(value, str) else None
    return None
