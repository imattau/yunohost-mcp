"""Repository-to-Concord-channel routing helpers.

This module deliberately contains no Concord cryptography or relay I/O.  It
provides the deterministic, safe part of the optional post-publication flow:
derive the repository name used by the Armada channel convention and select a
single active channel without fuzzy guessing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlsplit


class AmbiguousChannelError(ValueError):
    """More than one active channel matched the requested repository name."""


@dataclass(frozen=True)
class ChannelMatch:
    """The channel selected for a repository announcement."""

    repository_name: str
    channel_id: str
    channel_name: str
    private: bool = False


def normalize_channel_list(payload: Any) -> list[dict[str, Any]]:
    """Extract channel metadata into the routing module's small schema.

    Concord integrations may return either a bare channel array or a
    community/control-plane response containing ``channels``.  The protocol's
    stable field is ``channel_id``; accepting ``id`` as well keeps this
    boundary tolerant of Armada/UI-shaped responses without making routing
    depend on either client's full object model.
    """

    if isinstance(payload, dict):
        payload = payload.get("channels", [])
    if not isinstance(payload, list):
        return []

    channels: list[dict[str, Any]] = []
    for value in payload:
        if not isinstance(value, dict):
            continue
        channel_id = value.get("channel_id") or value.get("id")
        name = value.get("name") or value.get("channel_name")
        if not isinstance(channel_id, str) or not channel_id.strip():
            continue
        if not isinstance(name, str) or not name.strip():
            continue
        channels.append(
            {
                "id": channel_id.strip(),
                "name": name.strip(),
                "private": bool(value.get("private", False)),
                "deleted": value.get("deleted") is True,
            }
        )
    return channels


def repository_name(source: str) -> str:
    """Return the repository basename used by the channel naming convention.

    ``source`` may be a local package directory or a canonical repository URL.
    Only transport noise is removed: a repository's meaningful spelling,
    including a conventional ``_ynh`` suffix, is preserved.
    """

    value = source.strip()
    if not value:
        raise ValueError("repository source must not be empty")

    if "://" in value:
        path = urlsplit(value).path
    else:
        path = value

    name = PurePosixPath(path.rstrip("/")).name
    if name.endswith(".git"):
        name = name[:-4]
    if not name or name in {".", ".."}:
        raise ValueError("repository source does not contain a repository name")
    return name


def _channel_name(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    name = value.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else None


def match_repository_channel(
    repo_name: str,
    channels: Iterable[dict[str, Any]],
    *,
    aliases: dict[str, str] | None = None,
) -> ChannelMatch | None:
    """Select one active channel by exact repository-name match.

    Channel IDs are returned as the stable routing value.  Deleted channels,
    malformed entries, and channels without IDs are ignored.  Aliases are an
    explicit escape hatch for repositories whose channel intentionally has a
    different name; they are never inferred.
    """

    requested = repo_name.strip()
    if not requested:
        raise ValueError("repository name must not be empty")

    requested_key = requested.casefold()
    alias_target = (aliases or {}).get(requested, (aliases or {}).get(requested_key))
    target_key = (alias_target or requested).strip().casefold()

    matches: list[ChannelMatch] = []
    for channel in channels:
        if not isinstance(channel, dict) or channel.get("deleted") is True:
            continue
        name = _channel_name(channel)
        channel_id = channel.get("id") or channel.get("channel_id")
        if not name or not isinstance(channel_id, str) or not channel_id.strip():
            continue
        if name.casefold() != target_key:
            continue
        matches.append(
            ChannelMatch(
                repository_name=requested,
                channel_id=channel_id.strip(),
                channel_name=name,
                private=bool(channel.get("private", False)),
            )
        )

    if len(matches) > 1:
        raise AmbiguousChannelError(f"multiple active Concord channels match repository {requested!r}")
    return matches[0] if matches else None


def match_source_channel(
    source: str,
    channels: Iterable[dict[str, Any]],
    *,
    aliases: dict[str, str] | None = None,
) -> ChannelMatch | None:
    """Extract a repository name from ``source`` and match its channel."""

    return match_repository_channel(repository_name(source), channels, aliases=aliases)
