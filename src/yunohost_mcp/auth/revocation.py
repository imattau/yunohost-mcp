"""Independent delegation revocation (PLAN.md Phase 11).

A flat list of revoked delegation event ids, loaded from a TOML file.
Revoking one delegation this way doesn't touch the delegator's own
identity.toml entry (which would revoke *every* delegation they've ever
issued, past and future) - this is the finer-grained mechanism PLAN.md
means by "independently revocable".

Same "missing file -> empty, safe default" shape as identity.toml/policy.toml,
but note the direction of "safe" is opposite: an empty revocation list is
not deny-by-default, it just means nothing has been revoked yet - the
actual gate is the delegation's own expiry and its delegator's standing
(auth/delegation.py), not this file's presence.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

logger = logging.getLogger(__name__)


class RevocationConfigError(ValueError):
    """revoked_delegations.toml is malformed."""


def _load_revoked_ids(path: Path) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise RevocationConfigError(f"{path}: invalid TOML: {exc}") from exc
    ids = data.get("revoked", [])
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        raise RevocationConfigError(f"{path}: 'revoked' must be a list of event id strings")
    return frozenset(ids)


class RevocationStore:
    """Two modes, same shape as IdentityStore (auth/identity.py):

      - RevocationStore(ids) / RevocationStore.load(path): a fixed, static
        snapshot - what existing tests use.
      - RevocationStore.live(path): re-reads `path` on every is_revoked()/
        __len__() call, so an admin revoking a delegation takes effect on
        the next request, not only after a service restart. This is the
        more urgent of the two live-reload fixes: a revocation is a
        deliberate "take access away right now" action, and a stale cache
        here means a delegation the owner believed was revoked keeps
        working until someone thinks to restart the service.

    Fail-safe direction is the opposite of IdentityStore's: on a transient
    parse error, IdentityStore denies every identity (nothing verifies);
    here the safe default is to treat every event id as revoked (nothing is
    trusted) rather than silently reverting to "nothing has been revoked" -
    a malformed revoked_delegations.toml must never look identical to an
    empty one.
    """

    def __init__(self, revoked_event_ids: frozenset[str], *, live_path: Path | None = None) -> None:
        self._revoked = revoked_event_ids
        self._live_path = live_path

    @classmethod
    def load(cls, path: Path) -> RevocationStore:
        return cls(_load_revoked_ids(path))

    @classmethod
    def live(cls, path: Path) -> RevocationStore:
        return cls(frozenset(), live_path=path)

    def is_revoked(self, event_id: str) -> bool:
        if self._live_path is None:
            return event_id in self._revoked
        try:
            return event_id in _load_revoked_ids(self._live_path)
        except RevocationConfigError as exc:
            logger.error(
                "revoked_delegations.toml reload failed, treating all delegations as revoked until fixed: %s",
                exc,
            )
            return True

    def __len__(self) -> int:
        if self._live_path is None:
            return len(self._revoked)
        try:
            return len(_load_revoked_ids(self._live_path))
        except RevocationConfigError:
            return 0
