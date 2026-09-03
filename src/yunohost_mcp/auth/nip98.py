"""NIP-98 (HTTP Auth) verification.

https://github.com/nostr-protocol/nips/blob/master/98.md

A NIP-98 request carries an `Authorization: Nostr <base64(event json)>`
header, where the event is a kind-27235 event whose tags bind it to one
exact HTTP request:

  - ["u", "<absolute request url>"]
  - ["method", "<HTTP method, e.g. GET/POST>"]
  - ["payload", "<sha256 hex of the request body>"]   (present when there's a body)

Verification here proves identity only (a valid signature from `pubkey`
authored a request matching this exact method/url/body, recently, and not
replayed). It does not decide whether that pubkey is *allowed* to do
anything — that's Phase 3 (auth/identity.py + policy/roles.py).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass

from pydantic import ValidationError

from yunohost_mcp.auth.nostr import NostrEvent, NostrEventError, verify_event
from yunohost_mcp.auth.replay import ReplayCache, ReplayError

NIP98_KIND = 27235
DEFAULT_CLOCK_SKEW_SECONDS = 60


class Nip98Error(ValueError):
    """A request's NIP-98 Authorization header failed verification."""


@dataclass(frozen=True)
class Nip98Identity:
    """The result of a successful NIP-98 verification: identity only, no authority."""

    pubkey: str
    event_id: str
    created_at: int


def verify_nip98_request(
    *,
    authorization_header: str | None,
    method: str,
    url: str,
    body: bytes,
    replay_cache: ReplayCache,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: int | None = None,
) -> Nip98Identity:
    """Verify a NIP-98 Authorization header against the concrete request it claims to sign.

    Raises Nip98Error on any failure. Order of checks is deliberate: cheap
    structural checks first, signature next, replay check last (so a replay
    is only recorded once the event is otherwise fully valid).
    """
    if not authorization_header:
        raise Nip98Error("missing Authorization header")

    scheme, _, encoded = authorization_header.partition(" ")
    if scheme.lower() != "nostr" or not encoded:
        raise Nip98Error("Authorization header must be 'Nostr <base64-event>'")

    try:
        decoded = base64.b64decode(encoded, validate=True)
        raw = json.loads(decoded)
        event = NostrEvent.model_validate(raw)
    except (ValueError, ValidationError) as exc:
        raise Nip98Error(f"malformed NIP-98 event: {exc}") from exc

    if event.kind != NIP98_KIND:
        raise Nip98Error(f"expected kind {NIP98_KIND}, got {event.kind}")

    now = int(time.time()) if now is None else now
    if abs(now - event.created_at) > clock_skew_seconds:
        raise Nip98Error(
            f"event timestamp {event.created_at} outside {clock_skew_seconds}s "
            f"clock skew of server time {now}"
        )

    event_url = event.tag("u")
    if event_url != url:
        raise Nip98Error(f"'u' tag {event_url!r} does not match request url {url!r}")

    event_method = event.tag("method")
    if event_method is None or event_method.upper() != method.upper():
        raise Nip98Error(f"'method' tag {event_method!r} does not match request method {method!r}")

    if body:
        expected_payload = hashlib.sha256(body).hexdigest()
        event_payload = event.tag("payload")
        if event_payload != expected_payload:
            raise Nip98Error("'payload' tag does not match sha256 of request body")

    try:
        verify_event(event)
    except NostrEventError as exc:
        raise Nip98Error(str(exc)) from exc

    try:
        replay_cache.check_and_record(event.id)
    except ReplayError as exc:
        raise Nip98Error(str(exc)) from exc

    return Nip98Identity(pubkey=event.pubkey, event_id=event.id, created_at=event.created_at)
