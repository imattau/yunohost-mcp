"""Nostr capability delegation (PLAN.md Phase 11).

An identity.toml-mapped owner can hand a disposable agent identity a
delegation - a signed Nostr event granting a subset of the owner's own
scopes, to one specific agent pubkey, targeting one specific server, until
one specific expiry - without ever handing over their private key. The
agent authenticates with NIP-98 as always (auth/nip98.py; it signs its own
requests with its own key), and additionally presents the delegation event
via the `X-Nostr-Delegation` request header so auth/middleware.py can
resolve it.

This is not a standard NIP - kind 27236 is this project's own, chosen
adjacent to (but distinct from) NIP-98's 27235. PLAN.md's constraints,
enforced here:
  - "delegation must specify server" -> a "server" tag, checked against
    this server's own identity (auth/server_identity.py) exactly.
  - "delegation must expire" -> an "expiry" tag is required, not optional.
  - "delegation cannot grant permissions the signer lacks" -> the
    delegate's effective scopes are the *intersection* of the delegation's
    requested scopes and the delegator's own current scopes from
    identity.toml, not the requested scopes outright. A delegator whose
    own access has since been narrowed can't have granted more than they
    currently have, even if the delegation event predates that change.
  - "delegations should be independently revocable" -> checked against
    auth/revocation.py's RevocationStore by the delegation event's own id,
    independent of revoking the delegator's whole identity.toml entry
    (which also works, and revokes everything they ever delegated, but is
    coarser).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

from yunohost_mcp.auth.identity import IdentityRecord, IdentityStore
from yunohost_mcp.auth.nostr import NostrEvent, NostrEventError, verify_event
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.policy.scopes import Scope

DELEGATION_KIND = 27236
DEFAULT_MAX_LIFETIME_SECONDS = 30 * 24 * 3600  # 30 days: a delegation is a bearer credential once issued


class DelegationError(ValueError):
    """A delegation event is malformed, expired, revoked, targets the wrong
    server, doesn't name this delegate, or its delegator has no standing."""


@dataclass(frozen=True)
class DelegationClaim:
    """A structurally and cryptographically valid delegation event, before
    it's been checked against the delegator's own current standing."""

    event_id: str
    delegator_pubkey: str
    delegate_pubkey: str
    requested_scopes: frozenset[Scope]
    server_pubkey: str
    expires_at: int


def verify_delegation_event(
    event: NostrEvent,
    *,
    expected_delegate_pubkey: str,
    server_pubkey_hex: str,
    revocation_store: RevocationStore,
    now: int | None = None,
) -> DelegationClaim:
    """Structural + cryptographic checks only - does not consult
    identity.toml. Raises DelegationError on any failure."""
    if event.kind != DELEGATION_KIND:
        raise DelegationError(f"expected kind {DELEGATION_KIND}, got {event.kind}")

    try:
        verify_event(event)
    except NostrEventError as exc:
        raise DelegationError(str(exc)) from exc

    if revocation_store.is_revoked(event.id):
        raise DelegationError(f"delegation {event.id} has been revoked")

    delegate = event.tag("p")
    if delegate != expected_delegate_pubkey:
        raise DelegationError(
            f"delegation names delegate {delegate!r}, does not match the requesting pubkey {expected_delegate_pubkey!r}"
        )

    server = event.tag("server")
    if server != server_pubkey_hex:
        raise DelegationError(f"delegation targets server {server!r}, not this server ({server_pubkey_hex!r})")

    expiry_raw = event.tag("expiry")
    if expiry_raw is None:
        raise DelegationError("delegation has no 'expiry' tag - PLAN.md requires every delegation to expire")
    try:
        expires_at = int(expiry_raw)
    except ValueError:
        raise DelegationError(f"'expiry' tag is not a unix timestamp: {expiry_raw!r}") from None

    now = int(time.time()) if now is None else now
    if now >= expires_at:
        raise DelegationError(f"delegation expired at {expires_at} (now {now})")
    if expires_at - event.created_at > DEFAULT_MAX_LIFETIME_SECONDS:
        raise DelegationError(
            f"delegation lifetime ({expires_at - event.created_at}s) exceeds the maximum "
            f"({DEFAULT_MAX_LIFETIME_SECONDS}s) - issue a shorter-lived one"
        )

    scope_values = [t[1] for t in event.tags if len(t) >= 2 and t[0] == "scope"]
    if not scope_values:
        raise DelegationError("delegation grants no scopes ('scope' tags)")
    try:
        requested_scopes = frozenset(Scope(v) for v in scope_values)
    except ValueError as exc:
        raise DelegationError(f"delegation names an unknown scope: {exc}") from None

    return DelegationClaim(
        event_id=event.id,
        delegator_pubkey=event.pubkey,
        delegate_pubkey=delegate,
        requested_scopes=requested_scopes,
        server_pubkey=server,
        expires_at=expires_at,
    )


def resolve_delegated_identity(claim: DelegationClaim, *, identity_store: IdentityStore) -> IdentityRecord:
    """Look the delegator up in identity.toml and clip the claim's requested
    scopes down to what they actually currently have. Raises DelegationError
    if the delegator has no standing at all (unmapped or expired) - a
    delegation is only ever as good as its delegator's own current access."""
    delegator_record = identity_store.lookup(claim.delegator_pubkey)
    if delegator_record is None:
        raise DelegationError(f"delegator {claim.delegator_pubkey!r} is not in identity.toml")
    if delegator_record.is_expired():
        raise DelegationError(f"delegator {claim.delegator_pubkey!r}'s own identity has expired")

    effective_scopes = claim.requested_scopes & delegator_record.scopes
    if not effective_scopes:
        raise DelegationError(
            f"delegator {delegator_record.name!r} does not currently hold any of the requested scopes"
        )

    # Never outlive the delegator's own access, even if the delegation
    # event itself would otherwise still be valid.
    expires_at = claim.expires_at
    if delegator_record.expires is not None:
        expires_at = min(expires_at, int(delegator_record.expires.timestamp()))

    return IdentityRecord(
        pubkey=claim.delegate_pubkey,
        name=f"{delegator_record.name} (delegated)",
        roles=(),
        scopes=effective_scopes,
        expires=datetime.fromtimestamp(expires_at, tz=timezone.utc),
    )
