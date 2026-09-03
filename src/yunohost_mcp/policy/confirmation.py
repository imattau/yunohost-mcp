"""Confirmation model (PLAN.md Phase 6), extended with owner co-signing (Phase 13).

A destructive operation whose policy has require_confirmation=True doesn't
execute on first call: it returns a confirmation_required response
describing what it would do (operation_plan), plus a confirmation_id. A
second, separately-signed call to the same tool with that confirmation_id
executes it - but only if the id is unexpired, unused, and was issued to
this exact pubkey for this exact tool and these exact arguments.

Deliberately not "pass any truthy confirm=true flag": PLAN.md is explicit
that confirmations must be cryptographically bound to one exact operation,
not a vague yes. Binding here means every field of the request that
matters (pubkey, tool, arguments) is checked again at consume-time, not
just at issue-time - a confirmation_id alone proves nothing without the
identity behind the request that presents it (NIP-98 auth still runs on
that second request the same as any other).

Phase 13 adds owner co-signing for the highest-risk operations
(require_owner_signature in policy/rules.py): a pending ticket can be
`approve()`d by a *different* identity (server.py's approve_operation
tool, gated Scope.OWNER_APPROVE) before its original requester may
`consume()` it. approve() does not remove the ticket - only a fully
satisfied consume() (right pubkey/tool/arguments, and owner-approved if
required) does; a request missing only owner approval leaves the ticket
pending so the same agent can retry once it's been co-signed, without
losing the approval that's already been given.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any


class ConfirmationError(ValueError):
    """A confirmation_id is unknown, expired, already used, or doesn't match this request."""


@dataclass(frozen=True)
class ConfirmationTicket:
    confirmation_id: str
    pubkey: str
    tool: str
    arguments_hash: str
    plan: dict[str, Any]
    created_at: float
    expires_at: float
    owner_approved_by: str | None = None


def _hash_arguments(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()


class ConfirmationStore:
    """In-memory, single-process (see auth/replay.py's ReplayCache for the
    same caveat: a multi-worker deployment needs a shared store)."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl_seconds = ttl_seconds
        self._pending: dict[str, ConfirmationTicket] = {}

    def create(self, *, pubkey: str, tool: str, arguments: dict[str, Any], plan: dict[str, Any]) -> ConfirmationTicket:
        now = time.time()
        ticket = ConfirmationTicket(
            confirmation_id=f"confirm-{uuid.uuid4().hex[:20]}",
            pubkey=pubkey,
            tool=tool,
            arguments_hash=_hash_arguments(arguments),
            plan=plan,
            created_at=now,
            expires_at=now + self._ttl_seconds,
        )
        self._pending[ticket.confirmation_id] = ticket
        return ticket

    def approve(self, confirmation_id: str, *, approver_pubkey: str) -> ConfirmationTicket:
        """Owner co-signing (Phase 13): marks a pending ticket approved by
        `approver_pubkey`, without consuming it - the original requester
        still has to call consume() themselves to actually execute."""
        ticket = self._pending.get(confirmation_id)
        if ticket is None:
            raise ConfirmationError("unknown or already-used confirmation_id")
        if time.time() >= ticket.expires_at:
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation has expired")
        if ticket.pubkey == approver_pubkey:
            raise ConfirmationError(
                "the same identity that requested this operation cannot also approve it - "
                "owner co-signing requires a different identity"
            )
        updated = dataclasses.replace(ticket, owner_approved_by=approver_pubkey)
        self._pending[confirmation_id] = updated
        return updated

    def peek(self, confirmation_id: str) -> ConfirmationTicket:
        """Return a pending ticket without consuming it."""
        ticket = self._pending.get(confirmation_id)
        if ticket is None:
            raise ConfirmationError("unknown or already-used confirmation_id")
        if time.time() >= ticket.expires_at:
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation has expired")
        return ticket

    def consume(
        self,
        confirmation_id: str,
        *,
        pubkey: str,
        tool: str,
        arguments: dict[str, Any],
        require_owner_approval: bool = False,
    ) -> ConfirmationTicket:
        """One-shot on every outcome except "missing owner approval": every
        other failure (expired, wrong identity, wrong tool, wrong
        arguments) removes the ticket immediately, so a leaked/guessed
        confirmation_id can't be brute-forced by repeated attempts. Missing
        owner approval is not an attack signal - it's an expected, retriable
        state - so the ticket is left in place for a later, successful
        consume() once it's been approved.
        """
        ticket = self._pending.get(confirmation_id)
        if ticket is None:
            raise ConfirmationError("unknown or already-used confirmation_id")
        if time.time() >= ticket.expires_at:
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation has expired")
        if ticket.pubkey != pubkey:
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation was issued to a different identity")
        if ticket.tool != tool:
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation was issued for a different tool")
        if ticket.arguments_hash != _hash_arguments(arguments):
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation does not match these exact arguments")
        if require_owner_approval and ticket.owner_approved_by is None:
            raise ConfirmationError(
                "this operation requires owner co-signature - use approve_operation() first"
            )
        del self._pending[confirmation_id]
        return ticket

    def __len__(self) -> int:
        return len(self._pending)
