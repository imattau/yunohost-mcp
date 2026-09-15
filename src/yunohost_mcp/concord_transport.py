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
from nostr_sdk import Client, Event, Filter, Kind, PublicKey, RelayUrl, ReqTarget

from .auth.nostr import NostrEvent


@dataclass(frozen=True)
class RelayPublishResult:
    event_id: str
    relays: tuple[str, ...]


def _event_id(event: Any) -> str | None:
    """Return an event id from either an SDK event or a test-shaped mapping."""

    if isinstance(event, dict):
        value = event.get("id")
    else:
        value = getattr(event, "id", None)
    return value if isinstance(value, str) and value else None


def _normalize_relays(relays: list[str]) -> tuple[str, ...]:
    """Dedup/strip a relay list and require at least one non-empty entry."""

    relay_values = tuple(dict.fromkeys(relay.strip() for relay in relays if relay.strip()))
    if not relay_values:
        raise ValueError("at least one non-empty Concord relay is required")
    return relay_values


def _parse_author(pubkey_hex: str, *, label: str) -> PublicKey:
    """Parse an already-length-validated pubkey, normalizing SDK parse errors."""

    try:
        return PublicKey.parse(pubkey_hex)
    except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
        raise ValueError(f"{label} public key must be valid lowercase hex") from exc


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
    relay_values = _normalize_relays(relays)
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


async def _fetch_events(
    pubkey_hex: str,
    relays: list[str],
    *,
    kind: int,
    limit: int,
    identifier: str | None = None,
    timeout_seconds: float,
    client_factory: Callable[[], Any],
    pubkey_label: str,
    fetch_label: str,
) -> list[Any]:
    """Shared bounded, per-relay-failure-tolerant Concord event fetch.

    Fetches at most `limit` deduplicated events matching `kind` (and, for
    addressable kinds, `identifier`) authored by `pubkey_hex`, from each of
    `relays` independently - one relay's failure (a bad URL, a dropped
    connection, an SDK-side error) does not abort the others, matching what
    fetch_control_events originally did on its own. A caller only sees an
    error when every relay failed and none of them returned anything at all;
    otherwise it gets whatever was collected before the deadline.

    nostr-sdk applies `max_events` to the aggregate result set, but a single
    multi-relay fetch can still receive up to `max_events` from each relay -
    that would make the SDK raise "too many fetched events" before callers
    can deduplicate. Fetching each relay independently and capping the
    merged result locally avoids that.
    """

    if len(pubkey_hex) != 64:
        raise ValueError(f"{pubkey_label} public key must be 32-byte lowercase hex")
    if limit <= 0:
        raise ValueError("max_events must be positive")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    relay_values = _normalize_relays(relays)
    author = _parse_author(pubkey_hex, label=pubkey_label)

    filter_ = Filter().author(author).kind(Kind(kind)).limit(limit)
    if identifier is not None:
        filter_ = filter_.identifier(identifier)
    request = ReqTarget.auto([filter_])

    events: list[Any] = []
    seen_ids: set[str] = set()
    failures = 0

    try:
        with anyio.fail_after(timeout_seconds):
            for relay in relay_values:
                client = client_factory()
                try:
                    await client.add_relay(RelayUrl.parse(relay))
                    await client.connect()
                    try:
                        fetched = await client.fetch_events(
                            request,
                            timeout=timedelta(seconds=timeout_seconds),
                            max_events=limit,
                        )
                    except Exception:  # noqa: BLE001 - normalize SDK relay errors below
                        failures += 1
                        continue
                    for event in fetched:
                        event_id = _event_id(event)
                        if event_id is not None:
                            if event_id in seen_ids:
                                continue
                            seen_ids.add(event_id)
                        events.append(event)
                        if len(events) >= limit:
                            return events[:limit]
                except Exception:  # noqa: BLE001 - one bad relay must not block others
                    failures += 1
                finally:
                    await client.shutdown()
    except TimeoutError as exc:
        raise ValueError(f"timed out fetching {fetch_label}") from exc

    if events:
        return events
    if failures:
        raise ValueError(f"unable to fetch {fetch_label} from configured relays")
    return events


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

    return await _fetch_events(
        control_pubkey_hex,
        relays,
        kind=1059,
        limit=max_events,
        timeout_seconds=timeout_seconds,
        client_factory=client_factory,
        pubkey_label="control",
        fetch_label="Concord control events",
    )


async def fetch_invite_events(
    link_signer_pubkey_hex: str,
    relays: list[str],
    *,
    timeout_seconds: float = 30,
    client_factory: Callable[[], Any] = Client,
) -> list[Any]:
    """Fetch the bounded public CORD-05 bundle coordinate for one signer.

    Uses the same per-relay failure-tolerant fetch as fetch_control_events -
    previously this looped relays into one shared client and let any single
    relay's failure abort the whole fetch, unlike fetch_control_events's own
    per-relay tolerance; that drift is fixed by sharing the implementation.
    """

    return await _fetch_events(
        link_signer_pubkey_hex,
        relays,
        kind=33301,
        limit=1,
        identifier="",
        timeout_seconds=timeout_seconds,
        client_factory=client_factory,
        pubkey_label="link signer",
        fetch_label="Concord invite events",
    )


async def fetch_guestbook_events(
    guestbook_pubkey_hex: str,
    relays: list[str],
    *,
    max_events: int = 64,
    timeout_seconds: float = 30.0,
    client_factory: Callable[[], Any] = Client,
) -> list[Any]:
    """Fetch a bounded batch of Guestbook stream wraps for join verification.

    Uses the same per-relay failure-tolerant fetch as fetch_control_events -
    previously this looped relays into one shared client and let any single
    relay's failure abort the whole fetch, unlike fetch_control_events's own
    per-relay tolerance; that drift is fixed by sharing the implementation.
    """

    return await _fetch_events(
        guestbook_pubkey_hex,
        relays,
        kind=1059,
        limit=max_events,
        timeout_seconds=timeout_seconds,
        client_factory=client_factory,
        pubkey_label="guestbook",
        fetch_label="Concord guestbook events",
    )
