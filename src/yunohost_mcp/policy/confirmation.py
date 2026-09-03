"""Confirmation model (PLAN.md Phase 6).

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
"""

from __future__ import annotations

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

    def consume(self, confirmation_id: str, *, pubkey: str, tool: str, arguments: dict[str, Any]) -> ConfirmationTicket:
        """One-shot: the ticket is removed whether or not it turns out to be valid, so a
        leaked/guessed confirmation_id can't be brute-forced by repeated attempts."""
        ticket = self._pending.pop(confirmation_id, None)
        if ticket is None:
            raise ConfirmationError("unknown or already-used confirmation_id")
        if time.time() >= ticket.expires_at:
            raise ConfirmationError("confirmation has expired")
        if ticket.pubkey != pubkey:
            raise ConfirmationError("confirmation was issued to a different identity")
        if ticket.tool != tool:
            raise ConfirmationError("confirmation was issued for a different tool")
        if ticket.arguments_hash != _hash_arguments(arguments):
            raise ConfirmationError("confirmation does not match these exact arguments")
        return ticket

    def __len__(self) -> int:
        return len(self._pending)
