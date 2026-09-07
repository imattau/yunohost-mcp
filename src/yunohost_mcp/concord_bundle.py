"""Bounded validation of decrypted CORD-05 CommunityInvite bundles."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import time
from typing import Any
from urllib.parse import urlsplit


class ConcordBundleError(ValueError):
    """An invite bundle is malformed or fails its community identity check."""


@dataclass(frozen=True)
class ValidatedChannelGrant:
    id: str
    name: str
    epoch: int
    private: bool
    key: bytes | None = field(repr=False, default=None)


@dataclass(frozen=True)
class ValidatedInviteBundle:
    community_id: str
    owner: str
    control_pk: str | None
    root_epoch: int
    relays: tuple[str, ...]
    channels: tuple[ValidatedChannelGrant, ...]
    expires_at: int | None = None
    community_root: bytes = field(repr=False, default=b"")
    owner_salt: bytes = field(repr=False, default=b"")


def _hex_bytes(value: Any, *, label: str, length: int = 32) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2 or value != value.lower():
        raise ConcordBundleError(f"{label} must be lowercase {length}-byte hex")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ConcordBundleError(f"{label} must be lowercase {length}-byte hex") from exc


def _epoch(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ConcordBundleError(f"{label} must be an unsigned 64-bit integer")
    return value


def validate_invite_bundle(
    bundle: Any,
    *,
    max_channels: int = 256,
    max_relays: int = 5,
    now_ms: int | None = None,
) -> ValidatedInviteBundle:
    """Validate and normalize a decrypted CommunityInvite without joining."""

    if not isinstance(bundle, dict):
        raise ConcordBundleError("invite bundle must be an object")
    if max_channels <= 0 or max_relays <= 0:
        raise ValueError("bundle bounds must be positive")
    community_id = _hex_bytes(bundle.get("community_id"), label="community_id").hex()
    owner = _hex_bytes(bundle.get("owner"), label="owner").hex()
    owner_salt = _hex_bytes(bundle.get("owner_salt"), label="owner_salt")
    expected = hashlib.sha256(b"concord/community" + bytes.fromhex(owner) + owner_salt).hexdigest()
    if community_id != expected:
        raise ConcordBundleError("community_id does not match owner and owner_salt")
    community_root = _hex_bytes(bundle.get("community_root"), label="community_root")
    root_epoch = _epoch(bundle.get("root_epoch"), label="root_epoch")
    control_pk = bundle.get("control_pk")
    if control_pk is not None:
        control_pk = _hex_bytes(control_pk, label="control_pk").hex()
    relays = bundle.get("relays")
    if not isinstance(relays, list) or len(relays) > max_relays or any(not isinstance(relay, str) or not relay for relay in relays):
        raise ConcordBundleError("invite relays must be a bounded list of non-empty strings")
    for relay in relays:
        parsed_relay = urlsplit(relay)
        if parsed_relay.scheme not in {"ws", "wss"} or not parsed_relay.netloc or parsed_relay.query or parsed_relay.fragment:
            raise ConcordBundleError("invite relays must be absolute ws(s) URLs without query or fragment")
    expires_at = bundle.get("expires_at")
    if expires_at is not None:
        if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at < 0:
            raise ConcordBundleError("invite expires_at must be a non-negative Unix millisecond timestamp")
        if (int(time.time() * 1000) if now_ms is None else now_ms) >= expires_at:
            raise ConcordBundleError("Concord invite has expired")
    channels = bundle.get("channels")
    if not isinstance(channels, list) or len(channels) > max_channels:
        raise ConcordBundleError("invite channels exceed the configured bound")
    grants: list[ValidatedChannelGrant] = []
    channel_ids: set[str] = set()
    for channel in channels:
        if not isinstance(channel, dict):
            raise ConcordBundleError("invite channel entries must be objects")
        channel_id = _hex_bytes(channel.get("id"), label="channel id").hex()
        if channel_id in channel_ids:
            raise ConcordBundleError("invite contains duplicate channel IDs")
        channel_ids.add(channel_id)
        name = channel.get("name")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 64:
            raise ConcordBundleError("channel name must be non-empty and at most 64 UTF-8 bytes")
        key = channel.get("key")
        key_bytes = _hex_bytes(key, label="channel key") if key is not None else None
        grants.append(
            ValidatedChannelGrant(
                id=channel_id,
                name=name,
                epoch=_epoch(channel.get("epoch"), label="channel epoch"),
                private=key_bytes is not None,
                key=key_bytes,
            )
        )
    return ValidatedInviteBundle(
        community_id=community_id,
        owner=owner,
        control_pk=control_pk,
        root_epoch=root_epoch,
        relays=tuple(relays),
        channels=tuple(grants),
        expires_at=expires_at,
        community_root=community_root,
        owner_salt=owner_salt,
    )
