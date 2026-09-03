"""Identity: pubkey -> role/scope resolution (PLAN.md Phase 3), plus
request-scoped access to the resolved identity for the lifetime of one call.

A valid NIP-98 signature (Phase 2) proves *who* is asking. It never implies
*what* they may do — that's decided here, by looking the pubkey up in
identity.toml and resolving its roles to scopes. A pubkey with no entry, an
expired entry, or an entry naming an unknown role has zero scopes: this
module is deny-by-default.
"""

from __future__ import annotations

import logging
import tomllib
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

from yunohost_mcp.auth.npub import Bech32Error, npub_to_hex
from yunohost_mcp.policy.roles import UnknownRoleError, scopes_for_roles
from yunohost_mcp.policy.scopes import ALL_SCOPES, Scope


class IdentityConfigError(ValueError):
    """identity.toml is malformed, or references an unknown role."""


@dataclass(frozen=True)
class IdentityRecord:
    """One entry from identity.toml, resolved to its effective scopes."""

    pubkey: str  # hex
    name: str
    roles: tuple[str, ...]
    scopes: frozenset[Scope]
    expires: datetime | None = None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires is None:
            return False
        now = now or datetime.now(timezone.utc)
        return now >= self.expires


class IdentityStore:
    """pubkey (hex) -> IdentityRecord, loaded from identity.toml.

    Two modes:
      - IdentityStore(records) / IdentityStore.load(path): a fixed, static
        snapshot - what every existing test in this codebase uses, and fine
        for that (no disk access needed per lookup).
      - IdentityStore.live(path): re-reads `path` from disk on every
        lookup()/__len__() call. This is what create_http_app() actually
        uses - identity.toml is meant to be edited by an admin while the
        server is running (granting or revoking an identity), and a store
        that only ever reflects the file's state *at process startup*
        silently requires a full service restart for that to take effect,
        which is real, previously-shipped-wrong behavior (see git history)
        that undermines the entire "revoking an identity is how you take
        access away" story. Re-parsing a small TOML file per request is
        negligible cost for a low-volume control-plane API; simplicity (no
        cache/staleness bugs possible) beats the marginal I/O savings a
        cache would buy here.
    """

    def __init__(self, records: dict[str, IdentityRecord], *, live_path: Path | None = None) -> None:
        self._records = records
        self._live_path = live_path

    @classmethod
    def load(cls, path: Path) -> IdentityStore:
        return cls(_load_records(path))

    @classmethod
    def live(cls, path: Path) -> IdentityStore:
        return cls({}, live_path=path)

    def _current_records(self) -> dict[str, IdentityRecord]:
        if self._live_path is None:
            return self._records
        try:
            return _load_records(self._live_path)
        except IdentityConfigError as exc:
            # A mid-edit identity.toml (e.g. a typo, or a save caught
            # half-written) must not crash every in-flight request or lock
            # the whole server out until it's fixed - deny-by-default means
            # "nothing verifies" here, the same as an empty file, not "the
            # control plane itself breaks". The error is still loud, in the
            # logs, not swallowed silently.
            logger.error("identity.toml reload failed, denying all identities until fixed: %s", exc)
            return {}

    def lookup(self, pubkey_hex: str) -> IdentityRecord | None:
        return self._current_records().get(pubkey_hex)

    def pubkeys_with_role(self, role: str) -> list[str]:
        """All pubkeys whose identity.toml roles include `role`, ignoring
        per-identity expiry - used for owner bootstrap fallback
        (auth/owner.py), which is about picking a static default from
        config, not about authorizing a live request."""
        return [pubkey for pubkey, record in self._current_records().items() if role in record.roles]

    def __len__(self) -> int:
        return len(self._current_records())


def _load_records(path: Path) -> dict[str, IdentityRecord]:
    if not path.exists():
        return {}

    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise IdentityConfigError(f"{path}: invalid TOML: {exc}") from exc

    records: dict[str, IdentityRecord] = {}
    for raw_key, entry in data.get("identity", {}).items():
        pubkey = _resolve_key_to_hex(raw_key)
        roles = tuple(entry.get("roles", []))
        try:
            scopes = scopes_for_roles(roles)
        except UnknownRoleError as exc:
            raise IdentityConfigError(f"{path}: identity {raw_key!r}: {exc}") from exc

        expires_raw = entry.get("expires")
        expires = datetime.fromisoformat(expires_raw) if expires_raw else None

        records[pubkey] = IdentityRecord(
            pubkey=pubkey,
            name=entry.get("name", raw_key),
            roles=roles,
            scopes=scopes,
            expires=expires,
        )
    return records


def _resolve_key_to_hex(raw_key: str) -> str:
    if raw_key.startswith("nsec1"):
        # identity.toml keys are public identities to authorize, never
        # secrets - PLAN.md Phase 9: "private Nostr keys must never be
        # stored by yunohost-mcp". Reject loudly rather than let an
        # accidentally-pasted private key sit in a config file believing
        # it's being used as a pubkey (bech32-decoding it as an npub would
        # silently fail anyway with a confusing wrong-HRP error - this is
        # the same failure, named for what it actually is).
        raise IdentityConfigError(
            "identity.toml key looks like an nsec (private key), not an npub/hex pubkey - "
            "yunohost-mcp must never be given a private key"
        )
    if raw_key.startswith("npub1"):
        try:
            return npub_to_hex(raw_key)
        except Bech32Error as exc:
            raise IdentityConfigError(str(exc)) from exc
    return raw_key.lower()


@dataclass(frozen=True)
class AuthenticatedRequest:
    """Everything known about the caller of the current request.

    `pubkey`/`event_id`/`event_created_at` come from NIP-98 (Phase 2,
    authentication). `identity` is the resolved identity.toml record (Phase
    3, authorization) — None only transiently, between authentication and
    authorization resolution; the middleware never lets a request through
    to a tool without both set.
    """

    pubkey: str
    event_id: str
    event_created_at: int
    identity: IdentityRecord | None = field(default=None)

    @property
    def scopes(self) -> frozenset[Scope]:
        return self.identity.scopes if self.identity else frozenset()

    def has_scope(self, scope: Scope) -> bool:
        return scope in self.scopes


LOCAL_STDIO_IDENTITY = IdentityRecord(
    pubkey="local-stdio",
    name="local stdio operator",
    roles=("administrator",),
    scopes=ALL_SCOPES,
)
"""The implicit identity for the stdio transport.

Unlike http (NIP-98 + identity.toml, deny-by-default), stdio has no
transport-level auth at all: whoever can execute this process locally
already has the same access a `yunohost` CLI invocation would (same host,
same privilege boundary). Granting full scopes here makes that trust
explicit and auditable, rather than an implicit fallback inside
require_scope() for "no identity in context" — see server.py's stdio
branch, the only place this is set.
"""

LOCAL_STDIO_REQUEST = AuthenticatedRequest(
    pubkey=LOCAL_STDIO_IDENTITY.pubkey,
    event_id="",
    event_created_at=0,
    identity=LOCAL_STDIO_IDENTITY,
)

_current_request: ContextVar[AuthenticatedRequest | None] = ContextVar("current_request", default=None)


def set_current_request(request: AuthenticatedRequest | None) -> None:
    _current_request.set(request)


def get_current_request() -> AuthenticatedRequest | None:
    return _current_request.get()


def require_current_request() -> AuthenticatedRequest:
    request = get_current_request()
    if request is None:
        raise RuntimeError("no authenticated request in this context")
    return request
