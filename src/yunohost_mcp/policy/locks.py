"""Operation locking (PLAN.md Phase 5/6): at most one YunoHost write in
flight at a time, dispatched by this MCP server.

A single process-wide lock, not per-operation-type — the MVP goal is "do
not allow concurrent conflicting operations" (PLAN.md's explicit
constraint), and YunoHost's own lock file
(/var/run/moulinette_yunohost.lock, see PHASE0_INVESTIGATION.md) is
similarly coarse-grained. Non-blocking: a second write while one is in
flight fails fast with LockedError rather than queuing silently, so
callers get a clear, immediate answer instead of an MCP request that hangs
for an unknown amount of time.

Tool handlers run synchronously (mcp SDK runs them in a worker thread, not
on the event loop), so this uses threading.Lock, not asyncio.Lock.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager


class LockedError(RuntimeError):
    """Another write operation is already in progress."""


class WriteLock:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    @contextmanager
    def locked(self) -> Iterator[None]:
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            raise LockedError("another write operation is already in progress; try again shortly")
        try:
            yield
        finally:
            self._lock.release()
