"""Short-lived, identity-bound package-test sessions."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass


class PackageTestSessionError(ValueError):
    """A package-test session is missing, expired, or does not match."""


@dataclass(frozen=True)
class PackageTestSession:
    session_id: str
    pubkey: str
    source: str
    source_hash: str
    app_id: str
    created_at: float
    expires_at: float


def _source_hash(source: str) -> str:
    return hashlib.sha256(source.encode()).hexdigest()


class PackageTestSessionStore:
    """SQLite-backed store shared by the HTTP frontend and root broker."""

    def __init__(self, path, ttl_seconds: int = 1800) -> None:
        self.path = str(path)
        self.ttl_seconds = ttl_seconds
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS package_test_sessions ("
                "id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, source TEXT NOT NULL, "
                "source_hash TEXT NOT NULL, app_id TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL)"
            )
        os.chmod(self.path, 0o660)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def create(self, *, pubkey: str, source: str, app_id: str) -> PackageTestSession:
        now = time.time()
        session = PackageTestSession(
            session_id=f"ptest-{uuid.uuid4().hex[:20]}",
            pubkey=pubkey,
            source=source,
            source_hash=_source_hash(source),
            app_id=app_id,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        with self._connect() as db:
            db.execute(
                "INSERT INTO package_test_sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session.session_id, session.pubkey, session.source, session.source_hash,
                 session.app_id, session.created_at, session.expires_at),
            )
        return session

    def get(self, session_id: str, *, pubkey: str, source: str | None = None, app_id: str | None = None) -> PackageTestSession:
        with self._connect() as db:
            row = db.execute(
                "SELECT id, pubkey, source, source_hash, app_id, created_at, expires_at "
                "FROM package_test_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                raise PackageTestSessionError("unknown package-test session")
            session = PackageTestSession(*row)
            if time.time() >= session.expires_at:
                db.execute("DELETE FROM package_test_sessions WHERE id = ?", (session_id,))
                raise PackageTestSessionError("package-test session has expired")
            if session.pubkey != pubkey:
                raise PackageTestSessionError("package-test session belongs to a different identity")
            if source is not None and (source != session.source or _source_hash(source) != session.source_hash):
                raise PackageTestSessionError("package-test source does not match the prepared session")
            if app_id is not None and app_id != session.app_id:
                raise PackageTestSessionError("package-test app does not match the prepared session")
            return session

    def delete(self, session_id: str, *, pubkey: str) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM package_test_sessions WHERE id = ? AND pubkey = ?", (session_id, pubkey))


def session_path(config_dir):
    return config_dir / "package-test-sessions.sqlite"
