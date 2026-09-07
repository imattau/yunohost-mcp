"""Decode and fold the basic Concord Guestbook Join/Leave state."""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Iterable

from .auth.nostr import NostrEvent, UnsignedNostrEvent, compute_event_id, verify_event
from .concord_crypto import decrypt_self_conversation
from .concord_keys import GroupKeyMaterial


class GuestbookError(ValueError):
    """A Guestbook wrap or rumor is malformed or fails verification."""


@dataclass(frozen=True)
class GuestbookState:
    member: str
    status: str
    timestamp_ms: int
    rumor_id: str


def decode_guestbook_wrap(
    wrap: dict[str, Any],
    stream_key: GroupKeyMaterial,
) -> dict[str, Any]:
    """Verify and decrypt one Guestbook wrap into its unsigned rumor."""

    try:
        outer = NostrEvent.model_validate(wrap)
        if outer.kind != 1059 or outer.pubkey != stream_key.pubkey_hex:
            raise GuestbookError("unexpected Guestbook stream event")
        verify_event(outer)
        seal = NostrEvent.model_validate(json.loads(decrypt_self_conversation(stream_key, outer.content)))
        if seal.kind != 20013:
            raise GuestbookError("Guestbook requires an encrypted seal")
        verify_event(seal)
        rumor = UnsignedNostrEvent.model_validate(json.loads(decrypt_self_conversation(stream_key, seal.content)))
    except GuestbookError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize malformed/crypto input
        raise GuestbookError("invalid Guestbook wrap") from exc
    if rumor.pubkey != seal.pubkey or rumor.id != compute_event_id(rumor):
        raise GuestbookError("Guestbook seal does not bind its rumor")
    if rumor.kind not in {3306, 3309, 3312}:
        raise GuestbookError("unsupported Guestbook rumor kind")
    return rumor.model_dump()


def _millisecond(rumor: dict[str, Any]) -> int | None:
    tags = rumor.get("tags")
    if not isinstance(tags, list):
        return 0
    values = [tag[1] for tag in tags if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "ms"]
    if not values:
        return 0
    if len(values) != 1 or not isinstance(values[0], str) or not values[0].isdigit():
        return None
    value = int(values[0])
    return value if 0 <= value <= 999 else None


def fold_guestbook(
    rumors: Iterable[dict[str, Any]],
    *,
    now_ms: int | None = None,
    future_skew_ms: int = 3_600_000,
    authorize_kick=None,
    authorize_snapshot=None,
    banned_members: Iterable[str] = (),
) -> dict[str, GuestbookState]:
    """Fold Guestbook Join/Leave and authorized Kick rumors.

    ``authorize_kick`` receives a kind-3309 rumor and must independently apply
    CORD-04 rank, permission, target, and ``vac`` checks. Kicks are ignored
    when no authority predicate is supplied. Snapshots use the same pattern;
    ``banned_members`` is applied after folding.
    """

    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if future_skew_ms < 0:
        raise ValueError("future_skew_ms must not be negative")
    states: dict[str, GuestbookState] = {}
    for rumor in rumors:
        if not isinstance(rumor, dict) or rumor.get("kind") not in {3306, 3309, 3312}:
            continue
        kind = rumor.get("kind")
        member = rumor.get("pubkey")
        if kind == 3312:
            if authorize_snapshot is None or not authorize_snapshot(rumor):
                continue
            try:
                snapshot_members = json.loads(rumor.get("content", ""))
            except (TypeError, ValueError):
                continue
            if not isinstance(snapshot_members, list) or any(
                not isinstance(value, str) or len(value) != 64 for value in snapshot_members
            ):
                continue
            tags = rumor.get("tags")
            snap_tags = (
                [tag for tag in tags if isinstance(tag, list) and len(tag) >= 4 and tag[0] == "snap"]
                if isinstance(tags, list)
                else []
            )
            if len(snap_tags) != 1 or any(
                not isinstance(value, str) or not value.isdigit() for value in snap_tags[0][2:4]
            ):
                continue
            member = snapshot_members[0] if snapshot_members else "0" * 64
        else:
            snapshot_members = []
        if kind == 3309:
            if authorize_kick is None or not authorize_kick(rumor):
                continue
            tags = rumor.get("tags")
            targets = [
                tag[1]
                for tag in tags
                if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p" and isinstance(tag[1], str)
            ] if isinstance(tags, list) else []
            if len(targets) != 1:
                continue
            member = targets[0]
        rumor_id = rumor.get("id")
        content = rumor.get("content")
        millisecond = _millisecond(rumor)
        created_at = rumor.get("created_at")
        if (
            not isinstance(member, str)
            or len(member) != 64
            or not isinstance(rumor_id, str)
            or len(rumor_id) != 64
            or (kind == 3306 and content not in {"join", "leave"})
            or (kind == 3309 and content != "")
            or not isinstance(created_at, int)
            or millisecond is None
        ):
            continue
        timestamp_ms = created_at * 1000 + millisecond
        if timestamp_ms > now_ms + future_skew_ms:
            continue
        if kind == 3312:
            for snapshot_member in snapshot_members:
                candidate = GuestbookState(snapshot_member, "join", timestamp_ms, rumor_id)
                current = states.get(snapshot_member)
                if current is None or (candidate.timestamp_ms, candidate.rumor_id) > (current.timestamp_ms, current.rumor_id):
                    states[snapshot_member] = candidate
            continue
        candidate = GuestbookState(member, "leave" if kind == 3309 else content, timestamp_ms, rumor_id)
        current = states.get(member)
        if current is None or (candidate.timestamp_ms, candidate.rumor_id) > (current.timestamp_ms, current.rumor_id):
            states[member] = candidate
    banned = set(banned_members)
    return {member: state for member, state in states.items() if member not in banned}
