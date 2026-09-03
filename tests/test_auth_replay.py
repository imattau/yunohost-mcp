from __future__ import annotations

import pytest

from yunohost_mcp.auth.replay import ReplayCache, ReplayError


def test_first_use_recorded():
    cache = ReplayCache()
    cache.check_and_record("abc")
    assert len(cache) == 1


def test_second_use_rejected():
    cache = ReplayCache()
    cache.check_and_record("abc")
    with pytest.raises(ReplayError):
        cache.check_and_record("abc")


def test_expired_entry_pruned_and_reusable_id_slot():
    cache = ReplayCache(ttl_seconds=10)
    cache.check_and_record("abc", now=0.0)
    # Still within ttl.
    with pytest.raises(ReplayError):
        cache.check_and_record("abc", now=5.0)
    # Past ttl: entry pruned, same id can be recorded again (a *new* event
    # reusing an old id is not realistic, but this proves the cache doesn't
    # grow unboundedly).
    cache.check_and_record("abc", now=11.0)
    assert len(cache) == 1
