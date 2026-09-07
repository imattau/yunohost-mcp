"""Bounded relay transport for already-built Concord events.

This module intentionally accepts only a signed outer event. It does not read
keys, derive channels, or decide whether an announcement is authorized.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import json
from typing import Any, Callable

import anyio
from nostr_sdk import Client, Event, Filter, Kind, PublicKey, RelayUrl

from .auth.nostr import NostrEvent


@dataclass(frozen=True)
class RelayPublishResult:
    event_id: str
    relays: tuple[str, ...]


async def publish_signed_event(
    event: NostrEvent,
    relays: list[str],
    *,
    timeout_seconds: float = 30,
    client_factory: Callable[[], Any] = Client,
) -> RelayPublishResult:
    """Publish one signed event to configured relays within a hard deadline.

    The SDK sends the event to the configured relay set. A successful return
    means the SDK accepted the send operation; relay-level acceptance remains
    a separate verification concern.
    """

    if not relays:
        raise ValueError("at least one Concord relay is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    relay_values = tuple(dict.fromkeys(relay.strip() for relay in relays if relay.strip()))
    if not relay_values:
        raise ValueError("at least one non-empty Concord relay is required")
    sdk_event = Event.from_json(json.dumps(event.model_dump(), separators=(",", ":")))
    client = client_factory()
    try:
        with anyio.fail_after(timeout_seconds):
            for relay in relay_values:
                await client.add_relay(RelayUrl.parse(relay))
            await client.connect()
            await client.send_event(sdk_event)
    finally:
        await client.shutdown()
    return RelayPublishResult(event_id=event.id, relays=relay_values)


async def fetch_control_events(
    control_pubkey_hex: str,
    relays: list[str],
    *,
    max_events: int = 64,
    timeout_seconds: float = 30,
    client_factory: Callable[[], Any] = Client,
) -> list[Any]:
    """Fetch a bounded batch of CORD-01 Control Plane wraps.

    This only retrieves kind-1059 events by the already-derived control
    stream address. It does not decrypt, trust, or fold them; those checks
    belong to the Control Plane adapter.
    """

    if len(control_pubkey_hex) != 64:
        raise ValueError("control public key must be 32-byte lowercase hex")
    if max_events <= 0:
        raise ValueError("max_events must be positive")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    relay_values = tuple(dict.fromkeys(relay.strip() for relay in relays if relay.strip()))
    if not relay_values:
        raise ValueError("at least one non-empty Concord relay is required")
    try:
        author = PublicKey.parse(control_pubkey_hex)
    except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
        raise ValueError("control public key must be valid lowercase hex") from exc
    client = client_factory()
    try:
        with anyio.fail_after(timeout_seconds):
            for relay in relay_values:
                await client.add_relay(RelayUrl.parse(relay))
            await client.connect()
            return await client.fetch_events(
                Filter().author(author).kind(Kind(1059)).limit(max_events),
                timeout=timedelta(seconds=timeout_seconds),
                max_events=max_events,
            )
    finally:
        await client.shutdown()


async def fetch_invite_events(
    link_signer_pubkey_hex: str,
    relays: list[str],
    *,
    timeout_seconds: float = 30,
    client_factory: Callable[[], Any] = Client,
) -> list[Any]:
    """Fetch the bounded public CORD-05 bundle coordinate for one signer."""

    if len(link_signer_pubkey_hex) != 64:
        raise ValueError("link signer public key must be 32-byte lowercase hex")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    relay_values = tuple(dict.fromkeys(relay.strip() for relay in relays if relay.strip()))
    if not relay_values:
        raise ValueError("at least one non-empty Concord relay is required")
    try:
        author = PublicKey.parse(link_signer_pubkey_hex)
    except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
        raise ValueError("link signer public key must be valid lowercase hex") from exc
    client = client_factory()
    try:
        with anyio.fail_after(timeout_seconds):
            for relay in relay_values:
                await client.add_relay(RelayUrl.parse(relay))
            await client.connect()
            return await client.fetch_events(
                Filter().author(author).kind(Kind(33301)).identifier("").limit(1),
                timeout=timedelta(seconds=timeout_seconds),
                max_events=1,
            )
    finally:
        await client.shutdown()


async def fetch_guestbook_events(
    guestbook_pubkey_hex: str,
    relays: list[str],
    *,
    max_events: int = 64,
    timeout_seconds: float = 30.0,
    client_factory: Callable[[], Any] = Client,
) -> list[Any]:
    """Fetch a bounded batch of Guestbook stream wraps for join verification."""

    if len(guestbook_pubkey_hex) != 64:
        raise ValueError("guestbook public key must be 32-byte lowercase hex")
    if max_events <= 0:
        raise ValueError("max_events must be positive")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    relay_values = tuple(dict.fromkeys(relay.strip() for relay in relays if relay.strip()))
    if not relay_values:
        raise ValueError("at least one non-empty Concord relay is required")
    try:
        author = PublicKey.parse(guestbook_pubkey_hex)
    except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
        raise ValueError("guestbook public key must be valid lowercase hex") from exc
    client = client_factory()
    try:
        with anyio.fail_after(timeout_seconds):
            for relay in relay_values:
                await client.add_relay(RelayUrl.parse(relay))
            await client.connect()
            return await client.fetch_events(
                Filter().author(author).kind(Kind(1059)).limit(max_events),
                timeout=timedelta(seconds=timeout_seconds),
                max_events=max_events,
            )
    finally:
        await client.shutdown()
