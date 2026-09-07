"""Deterministic, authority-neutral folding of Concord channel metadata."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable, Iterable


_EDITION_LABEL = b"vector-community/v1/edition"
MANAGE_ROLES = 1 << 0
MANAGE_CHANNELS = 1 << 1


@dataclass(frozen=True)
class ChannelEdition:
    channel_id: str
    version: int
    previous: str | None
    edition_hash: str
    event_id: str
    name: str
    private: bool
    deleted: bool


@dataclass(frozen=True)
class _RosterEdition:
    event_id: str
    actor: str
    entity_id: str
    version: int
    previous: str | None
    edition_hash: str
    vsk: str
    content: dict[str, Any]
    event: dict[str, Any]


@dataclass(frozen=True)
class RosterMember:
    position: int
    permissions: int


def _vac_tag(tags: Any) -> list[str]:
    if not isinstance(tags, list):
        return []
    for tag in tags:
        if tag and isinstance(tag, list) and tag[0] == "vac":
            return [value for value in tag[1:4] if isinstance(value, str)]
    return []


def _parse_roster_edition(event: Any) -> _RosterEdition | None:
    if not isinstance(event, dict) or event.get("kind") != 3308:
        return None
    event_id = event.get("id")
    actor = event.get("pubkey")
    tags = event.get("tags")
    entity_id = _tag(tags, "eid")
    version_text = _tag(tags, "ev")
    vsk = _tag(tags, "vsk")
    content_text = event.get("content")
    if not all(isinstance(value, str) for value in (event_id, actor, entity_id, version_text, vsk, content_text)):
        return None
    if len(event_id) != 64 or len(actor) != 64 or len(entity_id) != 64:
        return None
    try:
        bytes.fromhex(actor + entity_id)
        version = int(version_text, 10)
        content = json.loads(content_text)
        previous = _tag(tags, "ep")
        digest = edition_hash(entity_id, version, previous, content_text)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if version <= 0 or not isinstance(content, dict):
        return None
    return _RosterEdition(event_id, actor, entity_id, version, previous, digest, vsk, content, event)


def _select_roster_heads(editions: list[_RosterEdition], accepted: set[str]) -> dict[tuple[str, str], _RosterEdition]:
    by_entity: dict[tuple[str, str], dict[int, list[_RosterEdition]]] = {}
    for edition in editions:
        if edition.event_id in accepted and edition.vsk in {"1", "3"}:
            by_entity.setdefault((edition.vsk, edition.entity_id), {}).setdefault(edition.version, []).append(edition)
    heads: dict[tuple[str, str], _RosterEdition] = {}
    for key, versions in by_entity.items():
        chosen: dict[int, _RosterEdition] = {}
        for version in sorted(versions):
            candidates = sorted(versions[version], key=lambda item: item.event_id)
            for candidate in candidates:
                if version == 1 and candidate.previous is None:
                    chosen[version] = candidate
                    break
                previous = chosen.get(version - 1)
                if previous is not None and candidate.previous == previous.edition_hash:
                    chosen[version] = candidate
                    break
        if chosen:
            heads[key] = chosen[max(chosen)]
    return heads


def _roster_members(heads: dict[tuple[str, str], _RosterEdition], owner: str) -> dict[str, RosterMember]:
    roles = {key[1]: edition.content for key, edition in heads.items() if key[0] == "1"}
    members: dict[str, RosterMember] = {owner: RosterMember(0, MANAGE_ROLES | MANAGE_CHANNELS)}
    for (vsk, _), edition in heads.items():
        if vsk != "3":
            continue
        member = edition.content.get("member")
        role_ids = edition.content.get("role_ids")
        if not isinstance(member, str) or len(member) != 64 or not isinstance(role_ids, list):
            continue
        role_states = [roles[role_id] for role_id in role_ids if isinstance(role_id, str) and role_id in roles]
        if not role_states:
            continue
        positions = [role.get("position") for role in role_states if isinstance(role.get("position"), int)]
        permissions = [role.get("permissions", "0") for role in role_states]
        if not positions:
            continue
        try:
            permission_bits = 0
            for value in permissions:
                permission_bits |= int(value)
        except (TypeError, ValueError):
            continue
        members[member] = RosterMember(min(positions), permission_bits)
    return members


def _has_current_grant_citation(edition: _RosterEdition, grants: dict[str, _RosterEdition]) -> bool:
    vac = _vac_tag(edition.event.get("tags"))
    if len(vac) != 3 or not vac[1].isdigit():
        return False
    grant = grants.get(vac[0])
    return bool(
        grant
        and grant.version == int(vac[1])
        and grant.edition_hash == vac[2]
        and grant.content.get("member") == edition.actor
    )


def build_roster_authorizer(
    events: Iterable[dict[str, Any]],
    *,
    owner: str,
    max_iterations: int = 128,
) -> Callable[[dict[str, Any]], bool]:
    """Build a CORD-04 authority predicate for Control Plane rumors.

    The fold starts with owner-signed Role/Grant editions and expands outward
    until no new authorized roster head appears. Non-owner actions must cite
    the exact selected Grant via ``vac``; channel edits additionally require
    ``MANAGE_CHANNELS``. Invalid or unresolved branches are rejected.
    """
    if len(owner) != 64 or owner != owner.lower():
        raise ValueError("owner must be lowercase 32-byte hex")
    parsed = [edition for event in events if (edition := _parse_roster_edition(event)) is not None]
    accepted: set[str] = {edition.event_id for edition in parsed if edition.actor == owner and edition.vsk in {"1", "3"}}
    for _ in range(max_iterations):
        heads = _select_roster_heads(parsed, accepted)
        members = _roster_members(heads, owner)
        grants = {edition.entity_id: edition for (vsk, _), edition in heads.items() if vsk == "3"}
        additions: set[str] = set()
        for edition in parsed:
            if edition.event_id in accepted or edition.vsk not in {"1", "3"}:
                continue
            actor = members.get(edition.actor)
            if actor is None or not actor.permissions & MANAGE_ROLES:
                continue
            if edition.actor != owner and not _has_current_grant_citation(edition, grants):
                continue
            if edition.vsk == "1":
                position = edition.content.get("position")
                if isinstance(position, int) and position > actor.position:
                    additions.add(edition.event_id)
                continue
            role_ids = edition.content.get("role_ids")
            if not isinstance(role_ids, list):
                continue
            roles = [heads.get(("1", role_id)) for role_id in role_ids if isinstance(role_id, str)]
            positions = [role.content.get("position") for role in roles if role is not None]
            if positions and all(isinstance(position, int) and position > actor.position for position in positions):
                additions.add(edition.event_id)
            elif not role_ids:
                target = edition.content.get("member")
                target_rank = members.get(target)
                if target_rank is not None and target_rank.position > actor.position:
                    additions.add(edition.event_id)
        if not additions - accepted:
            break
        accepted |= additions

    heads = _select_roster_heads(parsed, accepted)
    members = _roster_members(heads, owner)
    grants = {edition.entity_id: edition for (vsk, _), edition in heads.items() if vsk == "3"}

    def authorized(event: dict[str, Any]) -> bool:
        edition = _parse_roster_edition(event)
        if edition is None or edition.vsk != "2":
            return False
        if edition.actor == owner:
            return True
        member = members.get(edition.actor)
        if member is None or not member.permissions & MANAGE_CHANNELS:
            return False
        return _has_current_grant_citation(edition, grants)

    return authorized


def edition_hash(channel_id: str, version: int, previous: str | None, content: str) -> str:
    """Compute the CORD-04 edition hash over exact content bytes."""

    try:
        entity_id = bytes.fromhex(channel_id)
    except ValueError as exc:
        raise ValueError("channel_id must be lowercase 32-byte hex") from exc
    if len(entity_id) != 32 or channel_id != channel_id.lower():
        raise ValueError("channel_id must be lowercase 32-byte hex")
    if not 0 < version <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("edition version must fit a positive unsigned 64-bit integer")
    if previous is None:
        previous_bytes = b"\x00" + bytes(32)
    else:
        try:
            previous_bytes = b"\x01" + bytes.fromhex(previous)
        except ValueError as exc:
            raise ValueError("previous edition hash must be 32-byte hex") from exc
        if len(previous_bytes) != 33:
            raise ValueError("previous edition hash must be 32-byte hex")
    def length(value: bytes) -> bytes:
        return len(value).to_bytes(8, "big") + value

    content_bytes = content.encode("utf-8")
    preimage = length(_EDITION_LABEL) + entity_id + version.to_bytes(8, "big") + previous_bytes + length(content_bytes)
    return hashlib.sha256(preimage).hexdigest()


def _tag(tags: Any, name: str) -> str | None:
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == name and isinstance(tag[1], str):
            return tag[1]
    return None


def _parse_edition(event: Any) -> ChannelEdition | None:
    if not isinstance(event, dict) or event.get("kind") != 3308:
        return None
    if not isinstance(event.get("id"), str) or len(event["id"]) != 64:
        return None
    if _tag(event.get("tags"), "vsk") != "2":
        return None
    channel_id = _tag(event.get("tags"), "eid")
    version_text = _tag(event.get("tags"), "ev")
    content = event.get("content")
    if not isinstance(channel_id, str) or not isinstance(version_text, str) or not isinstance(content, str):
        return None
    try:
        version = int(version_text, 10)
        if str(version) != version_text or version <= 0:
            return None
        bytes.fromhex(channel_id)
        if len(channel_id) != 64 or channel_id != channel_id.lower():
            return None
        state = json.loads(content)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(state, dict) or not isinstance(state.get("name"), str):
        return None
    if len(state["name"].encode("utf-8")) > 64:
        return None
    previous = _tag(event.get("tags"), "ep")
    try:
        digest = edition_hash(channel_id, version, previous, content)
    except ValueError:
        return None
    return ChannelEdition(
        channel_id=channel_id,
        version=version,
        previous=previous,
        edition_hash=digest,
        event_id=event["id"],
        name=state["name"],
        private=state.get("private") is True,
        deleted=state.get("deleted") is True,
    )


def fold_channel_metadata(
    events: Iterable[dict[str, Any]],
    *,
    authorize: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    """Fold valid channel chains, with authority supplied by the caller.

    For each channel, the highest version with an intact predecessor chain is
    selected. Same-version conflicts converge on the lowest event ID. Deleted
    heads are omitted because deletion is terminal. When ``authorize`` is
    supplied, only rumors accepted by the caller's CORD-04 roster evaluator
    enter the fold; omitting it is intended only for transport/unit tests.
    """

    editions: dict[str, dict[int, list[ChannelEdition]]] = {}
    for event in events:
        if authorize is not None and not authorize(event):
            continue
        parsed = _parse_edition(event)
        if parsed is not None:
            editions.setdefault(parsed.channel_id, {}).setdefault(parsed.version, []).append(parsed)

    folded: list[ChannelEdition] = []
    for versions in editions.values():
        chosen: dict[int, ChannelEdition] = {}
        for version in sorted(versions):
            candidates = sorted(versions[version], key=lambda item: item.event_id)
            candidate = candidates[0]
            if version == 1:
                if candidate.previous is None:
                    chosen[version] = candidate
            elif version - 1 in chosen and candidate.previous == chosen[version - 1].edition_hash:
                chosen[version] = candidate
        if chosen:
            folded.append(chosen[max(chosen)])

    return [
        {
            "id": item.channel_id,
            "name": item.name,
            "private": item.private,
            "deleted": item.deleted,
            "version": item.version,
            "edition_hash": item.edition_hash,
        }
        for item in sorted(folded, key=lambda value: value.channel_id)
        if not item.deleted
    ]
