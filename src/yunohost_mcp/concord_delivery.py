"""Durable idempotency records for optional Concord announcements."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
import time


@dataclass(frozen=True)
class DeliveryRecord:
    idempotency_key: str
    event_id: str
    recorded_at: int


class ConcordDeliveryStore:
    """Small SQLite store keyed by the deterministic announcement key."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS concord_deliveries ("
                "idempotency_key TEXT PRIMARY KEY, event_id TEXT NOT NULL, recorded_at INTEGER NOT NULL)"
            )

    def get(self, idempotency_key: str) -> DeliveryRecord | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT idempotency_key, event_id, recorded_at FROM concord_deliveries WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return DeliveryRecord(*row) if row else None

    def record(self, idempotency_key: str, event_id: str) -> DeliveryRecord:
        recorded_at = int(time.time())
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT OR IGNORE INTO concord_deliveries (idempotency_key, event_id, recorded_at) VALUES (?, ?, ?)",
                (idempotency_key, event_id, recorded_at),
            )
            row = db.execute(
                "SELECT idempotency_key, event_id, recorded_at FROM concord_deliveries WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return DeliveryRecord(*row)
