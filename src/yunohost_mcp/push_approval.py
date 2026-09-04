"""Server-initiated ("push") owner approval.

Without this, the only way a require_owner_signature confirmation
(policy/rules.py; system.upgrade, backup restore, ...) ever reached the
owner's NIP-46 signer was if a human separately ran yunohost-mcp-approve
(or its config-panel equivalent) - notify.py's DM was only ever a text
nudge to go do that, never the actual signing request. That means the
signer's own "an app wants you to sign this" push prompt never appeared
on its own; someone always had to take a manual step first, which is the
opposite of what a pre-paired NIP-46 session is supposed to make possible.

This module closes that gap: the moment a require_owner_signature ticket
is created (policy/enforcement.py's set_owner_signature_pending_hook), it
reuses whatever session yunohost-mcp-approve pair already established
(config.py's approve_session_path - the same file the ynh packaging's
config-panel Pair action writes into, since that runs on this same box)
to open a live NIP-46 connection and ask the signer to sign a small,
human-readable approval event *right then* - producing a real push
prompt with no command to run and no button to click. If approved, the
ticket is marked approved directly (bypassing the approve_operation MCP
tool entirely, since we've already independently verified the owner's
own signature here - see _verify_and_extract below for exactly what's
checked).

Deliberately additive, never a replacement for approve_operation: no
session paired, a declined/expired push, a signer that's offline, or any
other failure here just leaves the ticket pending exactly as if this
module didn't exist - approve_operation (manual, via CLI or config
panel) remains available as it always has.

The owner's actual private key is never involved on this end either way
- app_keys here is the same disposable NIP-46 channel key
yunohost-mcp-approve pair already generated and persisted (see
approve.py's ApprovalSession/PendingOffer docstrings for why that's not
equivalent to holding the owner's nsec).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import anyio
from nostr_sdk import EventBuilder, Kind, NostrConnect, NostrConnectUri, Tag

from yunohost_mcp.approve import ApprovalSession

logger = logging.getLogger(__name__)

# Application-specific - not a real NIP, and never published to any relay
# by us (finalize_async returns the signed event directly to us over the
# already-paired NIP-46 channel; nothing here ever calls publish_event).
# Chosen clear of NIP-98 (27235, HTTP auth - approve.py's Nip46Auth uses
# that one for an unrelated purpose) so a signer app's own kind-specific
# handling never conflates the two.
PUSH_APPROVAL_KIND = 24243


def _build_push_content(
    *, tool: str, operation_plan: dict[str, Any], operation_hash: str, confirmation_id: str
) -> str:
    """What the owner actually sees in their signer app's approval prompt
    before they sign - most signer apps display an event's content
    directly, so this is the owner's real (and possibly only) chance to
    review what they're approving, same information approval_get would
    show a CLI user, delivered to where they're actually looking instead
    of requiring them to separately go find it."""
    lines = [f"yunohost-mcp: approve {tool!r}?"]
    action = operation_plan.get("action")
    if action:
        lines.append(f"action: {action}")
    warning = operation_plan.get("warning")
    if warning:
        lines.append(f"warning: {warning}")
    lines.append(f"operation_hash: {operation_hash}")
    lines.append(f"confirmation_id: {confirmation_id}")
    return "\n".join(lines)


async def _request_owner_signature_async(
    *,
    session_path: Path,
    owner_pubkey_hex: str,
    tool: str,
    operation_plan: dict[str, Any],
    operation_hash: str,
    confirmation_id: str,
    timeout_seconds: int,
) -> bool:
    """Never raises - every failure mode (no session, connection error,
    timeout, a mismatched or unverifiable response) just returns False,
    leaving the ticket exactly as pending as it already was."""
    session = ApprovalSession.load(session_path)
    if session is None or not session.bunker_uri:
        logger.info("push owner approval skipped for %s - no signer paired yet (%s)", confirmation_id, session_path)
        return False

    try:
        app_keys = session.app_keys()
        connect = NostrConnect(
            NostrConnectUri.parse(session.bunker_uri), app_keys, timedelta(seconds=timeout_seconds), None
        )
        content = _build_push_content(
            tool=tool, operation_plan=operation_plan, operation_hash=operation_hash, confirmation_id=confirmation_id
        )
        tags = [
            Tag.parse(["confirmation_id", confirmation_id]),
            Tag.parse(["operation_hash", operation_hash]),
        ]
        signed = await EventBuilder(Kind(PUSH_APPROVAL_KIND), content).tags(tags).finalize_async(connect)
    except Exception:
        logger.warning(
            "push owner approval request failed for %s (non-fatal - approve_operation remains available)",
            confirmation_id,
            exc_info=True,
        )
        return False

    return _verify_and_extract(
        signed, owner_pubkey_hex=owner_pubkey_hex, confirmation_id=confirmation_id, operation_hash=operation_hash
    )


def _verify_and_extract(signed: Any, *, owner_pubkey_hex: str, confirmation_id: str, operation_hash: str) -> bool:  # noqa: ANN401 - nostr_sdk's Event type
    """The actual proof-of-approval check, independent of anything
    approve_operation itself does (this bypasses that tool entirely - see
    module docstring) - so every property it would have relied on an
    inbound NIP-98-authenticated HTTP request to already guarantee has to
    be checked again here by hand: a valid signature, from exactly the
    configured owner, over exactly this ticket (not just *some* signed
    event - a signer that happened to sign something else for an
    unrelated reason must never be mistaken for approval)."""
    if not signed.verify():
        logger.warning("push owner approval signature failed verification for %s - refusing", confirmation_id)
        return False
    if signed.author().to_hex() != owner_pubkey_hex:
        logger.warning("push owner approval signer is not the configured owner for %s - refusing", confirmation_id)
        return False
    # Event.tags() is already a plain list of Tag in this nostr_sdk build,
    # not a Tags wrapper needing its own .to_vec() first - confirmed by
    # this bug actually firing in production (a real signed event, not
    # just fake unit-test data) before this fix.
    tag_values = {parts[0]: parts[1] for tag in signed.tags() if len(parts := tag.to_vec()) >= 2}
    if tag_values.get("confirmation_id") != confirmation_id or tag_values.get("operation_hash") != operation_hash:
        logger.warning("push owner approval event doesn't match the pending ticket %s - refusing", confirmation_id)
        return False
    return True


def request_owner_signature_in_background(
    *,
    session_path: Path,
    owner_pubkey_hex: str,
    tool: str,
    operation_plan: dict[str, Any],
    operation_hash: str,
    confirmation_id: str,
    timeout_seconds: int,
    on_approved: Callable[[], None],
) -> None:
    """Fire-and-forget: the tool call that triggered this has already
    returned its own confirmation_required response by the time this
    runs (policy/enforcement.py's set_owner_signature_pending_hook calls
    this synchronously right after issuing the ticket, but the actual
    live round trip - which can take up to timeout_seconds waiting on a
    human - happens on its own thread so that response is never delayed
    waiting on it.

    on_approved() is called (expected: ConfirmationStore.approve(...))
    only once the signature has been independently verified as the
    configured owner approving exactly this ticket - never speculatively."""
    def _run() -> None:
        import functools

        approved = anyio.run(
            functools.partial(
                _request_owner_signature_async,
                session_path=session_path,
                owner_pubkey_hex=owner_pubkey_hex,
                tool=tool,
                operation_plan=operation_plan,
                operation_hash=operation_hash,
                confirmation_id=confirmation_id,
                timeout_seconds=timeout_seconds,
            )
        )
        if not approved:
            return
        try:
            on_approved()
        except Exception:
            # e.g. the ticket expired in the (short) gap between the
            # signer approving and this callback running - log and move
            # on rather than crash a daemon thread silently.
            logger.warning("push owner approval: on_approved callback failed for %s", confirmation_id, exc_info=True)

    threading.Thread(target=_run, daemon=True, name="yunohost-mcp-push-approval").start()
