from __future__ import annotations

import threading

import pytest

from yunohost_mcp.policy.locks import LockedError, WriteLock


def test_lock_allows_sequential_use():
    lock = WriteLock()
    with lock.locked():
        pass
    with lock.locked():
        pass


def test_lock_rejects_reentry_while_held():
    lock = WriteLock()
    with lock.locked():
        with pytest.raises(LockedError):
            with lock.locked():
                pass


def test_lock_rejects_concurrent_holder_from_another_thread():
    lock = WriteLock()
    holder_ready = threading.Event()
    release = threading.Event()

    def hold():
        with lock.locked():
            holder_ready.set()
            release.wait(timeout=2)

    t = threading.Thread(target=hold)
    t.start()
    assert holder_ready.wait(timeout=2)

    with pytest.raises(LockedError):
        with lock.locked():
            pass

    release.set()
    t.join(timeout=2)

    # Lock is free again once the holder releases it.
    with lock.locked():
        pass
