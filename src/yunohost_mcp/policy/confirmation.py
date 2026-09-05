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
`approve()`d by the configured owner identity (auth/owner.py; server.py's
approve_operation tool, gated Scope.OWNER_APPROVE) before its original
requester may `consume()` it. approve() does not remove the ticket - only
a fully satisfied consume() (right pubkey/tool/arguments, and
owner-approved if required) does; a request missing only owner approval
leaves the ticket pending so the same agent can retry once it's been
co-signed, without losing the approval that's already been given.

v1 (owner-approval-plan.md) is `solo`-only: there is exactly one
configured owner, resolved by auth/owner.py, and approve() checks the
approver against that one pubkey - not "any identity other than the
requester". In the expected flow the requester is an agent operating
under its own delegated key (auth/delegation.py) and the owner approves
with their own npub via an external NIP-46 signer, so approver and
requester are naturally different identities; nothing here additionally
forces that, because a human owner calling a protected tool directly
(no agent) and then approving it via a separate signed call is also a
valid v1 flow - the security property is a separate, interactive signing
act, not a distinct pubkey per se.

Owner-approval tickets (require_owner_signature=True) get a longer TTL
than ordinary confirmations: the extra round trip involves a human
opening a separate NIP-46 signer app, which the default confirmation
window (sized for same-session retries) doesn't allow enough time for.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextvars import ContextVar
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
    operation_hash: str
    owner_approved_by: str | None = None


def _hash_arguments(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()


def _operation_hash(*, confirmation_id: str, pubkey: str, tool: str, arguments: dict[str, Any]) -> str:
    """Canonical digest of everything about this pending operation that an
    external approval helper (owner-approval-plan.md) needs to bind its
    signature to, independent of this store's own internal fields (e.g.
    arguments_hash) so it stays stable if this module's internals change.
    Not yet exposed through a dedicated read tool (that's approval_get /
    approval_status, a later slice) - computed here now so every ticket
    already carries it."""
    canonical = {
        "confirmation_id": confirmation_id,
        "requester_pubkey": pubkey,
        "tool": tool,
        "arguments": arguments,
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, default=str).encode()).hexdigest()


class ConfirmationStore:
    """In-memory, single-process (see auth/replay.py's ReplayCache for the
    same caveat: a multi-worker deployment needs a shared store). v1
    (owner-approval-plan.md) accepts this for a single-operator deployment
    rather than adding persistence - documented as a real limitation, not
    silently papered over."""

    def __init__(self, ttl_seconds: int = 300, *, owner_approval_ttl_seconds: int | None = None) -> None:
        self._ttl_seconds = ttl_seconds
        # Owner-approval tickets (require_owner_signature) need enough time
        # for a human to open a separate NIP-46 signer app and act, not
        # just enough for a same-session confirm-then-retry - defaults to
        # the ordinary TTL when not given a longer one explicitly.
        self._owner_approval_ttl_seconds = (
            owner_approval_ttl_seconds if owner_approval_ttl_seconds is not None else ttl_seconds
        )
        self._pending: dict[str, ConfirmationTicket] = {}

    def create(
        self,
        *,
        pubkey: str,
        tool: str,
        arguments: dict[str, Any],
        plan: dict[str, Any],
        require_owner_signature: bool = False,
    ) -> ConfirmationTicket:
        now = time.time()
        confirmation_id = f"confirm-{uuid.uuid4().hex[:20]}"
        ttl = self._owner_approval_ttl_seconds if require_owner_signature else self._ttl_seconds
        ticket = ConfirmationTicket(
            confirmation_id=confirmation_id,
            pubkey=pubkey,
            tool=tool,
            arguments_hash=_hash_arguments(arguments),
            plan=plan,
            created_at=now,
            expires_at=now + ttl,
            operation_hash=_operation_hash(
                confirmation_id=confirmation_id, pubkey=pubkey, tool=tool, arguments=arguments
            ),
        )
        self._pending[ticket.confirmation_id] = ticket
        return ticket

    def approve(self, confirmation_id: str, *, approver_pubkey: str, owner_pubkey: str) -> ConfirmationTicket:
        """Owner co-signing (Phase 13, narrowed to v1's `solo` profile by
        owner-approval-plan.md): marks a pending ticket approved, without
        consuming it - the original requester still has to call consume()
        themselves to actually execute. `owner_pubkey` is the one identity
        (auth/owner.py) allowed to approve; server.py's approve_operation
        resolves it fresh on every call and passes it in here rather than
        this store owning owner configuration itself."""
        ticket = self._pending.get(confirmation_id)
        if ticket is None:
            raise ConfirmationError("unknown or already-used confirmation_id")
        if time.time() >= ticket.expires_at:
            del self._pending[confirmation_id]
            raise ConfirmationError("confirmation has expired")
        if approver_pubkey != owner_pubkey:
            raise ConfirmationError(
                "approver is not the configured owner - owner co-signing requires the exact "
                "configured owner identity to sign the approval"
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
        defer: bool = False,
    ) -> ConfirmationTicket:
        """Validate a ticket, consuming it immediately unless ``defer`` is
        true. The broker uses deferred consumption so a failed privileged
        operation does not burn an otherwise valid approval ticket. Every
        validation failure (expired, wrong identity, wrong tool, or wrong
        arguments) still removes the ticket immediately, so a leaked/guessed
        confirmation_id cannot be brute-forced by repeated attempts. Missing
        owner approval is not an attack signal - it is an expected, retriable
        state - so the ticket is left in place for a later successful
        consume() once it has been approved.
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
        if not defer:
            del self._pending[confirmation_id]
        return ticket

    def finalize(self, confirmation_id: str) -> None:
        """Consume a ticket previously validated with ``defer=True``."""
        if confirmation_id not in self._pending:
            raise ConfirmationError("unknown or already-used confirmation_id")
        del self._pending[confirmation_id]

    def __len__(self) -> int:
        return len(self._pending)


class SQLiteConfirmationStore:
    """Cross-process confirmation store for the frontend and root helper.

    SQLite supplies the transaction boundary that the original in-memory
    store cannot provide once MCP and YunoHost execution live in separate
    processes. The public method contract intentionally mirrors
    ``ConfirmationStore`` so policy code does not care which deployment mode
    is active.
    """

    def __init__(self, path, ttl_seconds: int = 300, *, owner_approval_ttl_seconds: int | None = None) -> None:
        self.path = str(path)
        self._ttl_seconds = ttl_seconds
        self._owner_approval_ttl_seconds = owner_approval_ttl_seconds or ttl_seconds
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS confirmations ("
                "id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, tool TEXT NOT NULL, arguments_hash TEXT NOT NULL, "
                "plan TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, operation_hash TEXT NOT NULL, "
                "owner_approved_by TEXT)"
            )
        # The file contains confirmation plans and operation hashes shared by
        # the unprivileged frontend and root helper. Keep it accessible only
        # to the configured service owner/group, regardless of which process
        # creates it first or what the process umask happens to be.
        os.chmod(self.path, 0o660)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def create(self, *, pubkey, tool, arguments, plan, require_owner_signature=False):
        now = time.time()
        confirmation_id = f"confirm-{uuid.uuid4().hex[:20]}"
        ticket = ConfirmationTicket(
            confirmation_id=confirmation_id, pubkey=pubkey, tool=tool,
            arguments_hash=_hash_arguments(arguments), plan=plan, created_at=now,
            expires_at=now + (self._owner_approval_ttl_seconds if require_owner_signature else self._ttl_seconds),
            operation_hash=_operation_hash(confirmation_id=confirmation_id, pubkey=pubkey, tool=tool, arguments=arguments),
        )
        with self._connect() as db:
            db.execute("INSERT INTO confirmations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", self._row(ticket))
        return ticket

    def approve(self, confirmation_id, *, approver_pubkey, owner_pubkey):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            ticket = self._get(db, confirmation_id)
            self._check_live(db, ticket)
            if approver_pubkey != owner_pubkey:
                db.rollback()
                raise ConfirmationError("approver is not the configured owner - owner co-signing requires the exact configured owner identity to sign the approval")
            db.execute("UPDATE confirmations SET owner_approved_by=? WHERE id=?", (approver_pubkey, confirmation_id))
            db.commit()
            return dataclasses.replace(ticket, owner_approved_by=approver_pubkey)

    def peek(self, confirmation_id):
        with self._connect() as db:
            ticket = self._get(db, confirmation_id)
            self._check_live(db, ticket)
            return ticket

    def consume(self, confirmation_id, *, pubkey, tool, arguments, require_owner_approval=False, defer=False):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            ticket = self._get(db, confirmation_id)
            self._check_live(db, ticket)
            if ticket.pubkey != pubkey:
                self._delete_and_raise(db, confirmation_id, "confirmation was issued to a different identity")
            if ticket.tool != tool:
                self._delete_and_raise(db, confirmation_id, "confirmation was issued for a different tool")
            if ticket.arguments_hash != _hash_arguments(arguments):
                self._delete_and_raise(db, confirmation_id, "confirmation does not match these exact arguments")
            if require_owner_approval and ticket.owner_approved_by is None:
                db.rollback()
                raise ConfirmationError("this operation requires owner co-signature - use approve_operation() first")
            if not defer:
                db.execute("DELETE FROM confirmations WHERE id=?", (confirmation_id,))
            db.commit()
            return ticket

    def finalize(self, confirmation_id):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM confirmations WHERE id=?", (confirmation_id,)).fetchone() is None:
                db.rollback()
                raise ConfirmationError("unknown or already-used confirmation_id")
            db.execute("DELETE FROM confirmations WHERE id=?", (confirmation_id,))
            db.commit()

    def __len__(self):
        with self._connect() as db:
            return db.execute("SELECT COUNT(*) FROM confirmations").fetchone()[0]

    @staticmethod
    def _row(ticket):
        return (ticket.confirmation_id, ticket.pubkey, ticket.tool, ticket.arguments_hash, json.dumps(ticket.plan), ticket.created_at, ticket.expires_at, ticket.operation_hash, ticket.owner_approved_by)

    @staticmethod
    def _get(db, confirmation_id):
        row = db.execute("SELECT * FROM confirmations WHERE id=?", (confirmation_id,)).fetchone()
        if row is None:
            raise ConfirmationError("unknown or already-used confirmation_id")
        return ConfirmationTicket(row[0], row[1], row[2], row[3], json.loads(row[4]), row[5], row[6], row[7], row[8])

    @staticmethod
    def _check_live(db, ticket):
        if time.time() >= ticket.expires_at:
            db.execute("DELETE FROM confirmations WHERE id=?", (ticket.confirmation_id,))
            db.commit()
            raise ConfirmationError("confirmation has expired")

    @staticmethod
    def _delete_and_raise(db, confirmation_id, message):
        db.execute("DELETE FROM confirmations WHERE id=?", (confirmation_id,))
        db.commit()
        raise ConfirmationError(message)


_consumed_ticket: ContextVar[ConfirmationTicket | None] = ContextVar("consumed_confirmation_ticket", default=None)
"""Carries the ConfirmationTicket policy/enforcement.py's require_confirmation
just consumed for the currently-executing tool call over to
audit/decorator.py's audited_write, which wraps require_confirmation from
the outside (see server.py's decoration order: @audited_write always
sits above @require_confirmation) - so it can record owner_approved_by
into the write's own audit entry without either module changing what it
returns to the other. Plain module-global ContextVar, not a token-based
push/pop stack: set_consumed_ticket()/pop_consumed_ticket() below are the
only two call sites, always used as a single set-then-pop pair within one
tool call, the same pattern auth/identity.py's _current_request uses."""


def set_consumed_ticket(ticket: ConfirmationTicket | None) -> None:
    _consumed_ticket.set(ticket)


def pop_consumed_ticket() -> ConfirmationTicket | None:
    """Read-and-clear: audited_write calls this exactly once per call, on
    every exit path (success, lock contention, exception), so a value
    never leaks into an unrelated later call on the same thread."""
    ticket = _consumed_ticket.get()
    _consumed_ticket.set(None)
    return ticket
