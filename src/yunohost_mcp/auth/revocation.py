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

import tomllib
from pathlib import Path


class RevocationConfigError(ValueError):
    """revoked_delegations.toml is malformed."""


class RevocationStore:
    def __init__(self, revoked_event_ids: frozenset[str]) -> None:
        self._revoked = revoked_event_ids

    @classmethod
    def load(cls, path: Path) -> RevocationStore:
        if not path.exists():
            return cls(frozenset())
        try:
            data = tomllib.loads(path.read_text())
        except tomllib.TOMLDecodeError as exc:
            raise RevocationConfigError(f"{path}: invalid TOML: {exc}") from exc
        ids = data.get("revoked", [])
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise RevocationConfigError(f"{path}: 'revoked' must be a list of event id strings")
        return cls(frozenset(ids))

    def is_revoked(self, event_id: str) -> bool:
        return event_id in self._revoked

    def __len__(self) -> int:
        return len(self._revoked)
