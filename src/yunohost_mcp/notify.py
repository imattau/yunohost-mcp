"""Optional encrypted-DM notification (owner-approval-plan.md's "Optional
encrypted-DM delivery") for a pending owner-signature confirmation.

Never authoritative: approve_operation (server.py) is checked entirely on
its own - a valid NIP-98-signed request from the configured owner,
matched against the confirmation ticket - independent of whether this
notification was ever built, sent, delivered, or read. This module exists
only so the owner finds out sooner than "the agent happens to mention it",
not to gate anything.

Sends a real NIP-17 private direct message (nip17_make_private_msg:
sealed and gift-wrapped per NIP-59, not a bare NIP-04/NIP-44 note with
sender/recipient metadata exposed on the relay) from this server's own
Nostr identity (auth/server_identity.py) to the configured owner, so it
shows up in whatever Nostr client the owner already uses for DMs - not
just the approval helper.

Disabled by default (config.py's owner_notify_relays is empty) and
always best-effort: a relay outage or malformed config must never affect
the actual operation this notifies about, so notify_owner_best_effort()
catches everything and only ever logs.
"""

from __future__ import annotations

import logging

import anyio
from nostr_sdk import Client, Event, Keys, PublicKey, RelayUrl, nip17_make_private_msg

logger = logging.getLogger(__name__)


def parse_relay_list(raw: str) -> list[str]:
    """Comma-separated relay URLs - same convention as config.py's
    catalog_relays (yunohost/adapter.py's _catalog_relays)."""
    return [relay.strip() for relay in raw.split(",") if relay.strip()]


def build_notification_event(
    *,
    server_secret_key_hex: str,
    owner_pubkey_hex: str,
    confirmation_id: str,
    tool: str,
    expires_at: float,
) -> Event:
    keys = Keys.parse(server_secret_key_hex)
    receiver = PublicKey.parse(owner_pubkey_hex)
    message = (
        f"yunohost-mcp: {tool!r} is waiting for your approval.\n"
        f"confirmation_id: {confirmation_id}\n"
        f"expires_at: {expires_at}\n"
        "Review and approve with yunohost-mcp-approve - this message is a "
        "notification only, not itself an approval."
    )
    return nip17_make_private_msg(keys, receiver, message)


async def _publish(event: Event, relays: list[str]) -> None:
    client = Client()
    try:
        for relay in relays:
            await client.add_relay(RelayUrl.parse(relay))
        await client.connect()
        await client.send_event(event)
    finally:
        await client.shutdown()


def notify_owner_best_effort(
    *,
    server_secret_key_hex: str,
    owner_pubkey_hex: str,
    relays: list[str],
    confirmation_id: str,
    tool: str,
    expires_at: float,
) -> None:
    """Never raises. A disabled configuration (empty `relays`) is a
    silent, correct no-op - not a degraded state worth logging."""
    if not relays:
        return
    try:
        event = build_notification_event(
            server_secret_key_hex=server_secret_key_hex,
            owner_pubkey_hex=owner_pubkey_hex,
            confirmation_id=confirmation_id,
            tool=tool,
            expires_at=expires_at,
        )
        anyio.run(_publish, event, relays)
    except Exception:
        # Best-effort by design (see module docstring) - the operation
        # this would have notified about has already been offered to its
        # caller as a normal confirmation_required response either way.
        logger.warning("owner approval notification failed (non-fatal)", exc_info=True)
