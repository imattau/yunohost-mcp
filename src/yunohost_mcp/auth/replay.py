"""Replay protection: reject Nostr event ids that have already been used.

Single-process, in-memory TTL cache. Sufficient for a single yunohost-mcp
instance (the intended deployment per PLAN.md — one MCP daemon per YunoHost
box). If this ever runs as multiple worker processes behind a shared
endpoint, this cache must move to a shared store (e.g. Redis) or replay
protection silently weakens to "per worker" instead of "per server".
"""

from __future__ import annotations

import time


class ReplayError(ValueError):
    """An event id has already been used, or is otherwise not fresh enough."""


class ReplayCache:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    def check_and_record(self, event_id: str, *, now: float | None = None) -> None:
        """Raise ReplayError if event_id was already recorded; else record it."""
        now = time.monotonic() if now is None else now
        self._prune(now)
        if event_id in self._seen:
            raise ReplayError(f"event id already used: {event_id}")
        self._seen[event_id] = now + self._ttl_seconds

    def _prune(self, now: float) -> None:
        expired = [eid for eid, expiry in self._seen.items() if expiry <= now]
        for eid in expired:
            del self._seen[eid]

    def __len__(self) -> int:
        return len(self._seen)
