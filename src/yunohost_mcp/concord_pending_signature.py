"""Short-lived, identity-bound holding area for a split Concord envelope.

``catalog_announce_draft``/``armada_join_draft`` compute everything a
CORD-01 chat or CORD-02 join envelope needs except the one Schnorr
signature only the caller's own key can produce (see concord_envelope.py's
and concord_membership.py's module docstrings). This store holds that
in-progress state between the draft call and the matching
``*_submit`` call, scoped to the exact pubkey that requested it and
single-use like policy/package_sessions.py's PackageTestSessionStore.

The stream/guestbook key needed to finish the wrap layer is genuinely
secret channel key material, and it is stored here in plaintext for the
TTL window - the same trust boundary (root-owned file under config_dir)
as every other credential-adjacent store in this codebase, but worth a
second look before relying on this in a hostile-multi-tenant deployment.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class PendingSignatureError(ValueError):
    """A pending signature draft is missing, expired, or does not match."""


@dataclass(frozen=True)
class PendingSignature:
    draft_id: str
    pubkey: str
    purpose: str
    rumor: dict[str, Any]
    seal_template: dict[str, Any]
    stream_key: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    expires_at: float = 0.0


class PendingSignatureStore:
    """SQLite-backed store shared by the HTTP frontend and root broker."""

    def __init__(self, path, ttl_seconds: int = 300) -> None:
        self.path = str(path)
        self.ttl_seconds = ttl_seconds
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS pending_signatures ("
                "id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, purpose TEXT NOT NULL, "
                "rumor TEXT NOT NULL, seal_template TEXT NOT NULL, stream_key TEXT NOT NULL, "
                "context TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL)"
            )
        os.chmod(self.path, 0o660)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def create(
        self,
        *,
        pubkey: str,
        purpose: str,
        rumor: dict[str, Any],
        seal_template: dict[str, Any],
        stream_key: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> PendingSignature:
        now = time.time()
        pending = PendingSignature(
            draft_id=f"armada-draft-{uuid.uuid4().hex[:20]}",
            pubkey=pubkey,
            purpose=purpose,
            rumor=rumor,
            seal_template=seal_template,
            stream_key=stream_key,
            context=context or {},
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        with self._connect() as db:
            db.execute(
                "INSERT INTO pending_signatures VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pending.draft_id,
                    pending.pubkey,
                    pending.purpose,
                    json.dumps(pending.rumor),
                    json.dumps(pending.seal_template),
                    json.dumps(pending.stream_key),
                    json.dumps(pending.context),
                    pending.created_at,
                    pending.expires_at,
                ),
            )
        return pending

    def consume(self, draft_id: str, *, pubkey: str, purpose: str) -> PendingSignature:
        """Return and delete one pending draft - single use.

        Raises PendingSignatureError if it does not exist, has expired, was
        issued to a different pubkey, or is for a different purpose - the
        anti-impersonation and anti-confusion checks a submit call needs.
        """
        with self._connect() as db:
            row = db.execute(
                "SELECT id, pubkey, purpose, rumor, seal_template, stream_key, context, created_at, expires_at "
                "FROM pending_signatures WHERE id = ?",
                (draft_id,),
            ).fetchone()
            if row is None:
                raise PendingSignatureError("unknown pending signature draft")
            db.execute("DELETE FROM pending_signatures WHERE id = ?", (draft_id,))
            (
                stored_id,
                stored_pubkey,
                stored_purpose,
                rumor_json,
                seal_template_json,
                stream_key_json,
                context_json,
                created_at,
                expires_at,
            ) = row
            if time.time() >= expires_at:
                raise PendingSignatureError("pending signature draft has expired")
            if stored_pubkey != pubkey:
                raise PendingSignatureError("pending signature draft belongs to a different identity")
            if stored_purpose != purpose:
                raise PendingSignatureError("pending signature draft is for a different operation")
            return PendingSignature(
                draft_id=stored_id,
                pubkey=stored_pubkey,
                purpose=stored_purpose,
                rumor=json.loads(rumor_json),
                seal_template=json.loads(seal_template_json),
                stream_key=json.loads(stream_key_json),
                context=json.loads(context_json),
                created_at=created_at,
                expires_at=expires_at,
            )
