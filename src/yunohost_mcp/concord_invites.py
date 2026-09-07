"""Safe parsing of Concord shareable invite references."""

from __future__ import annotations

from dataclasses import dataclass, field
import base64
import json
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from coincurve import PublicKeyXOnly
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nostr_sdk import PublicKey, SecretKey, nip44_decrypt

from .concord_bundle import ValidatedInviteBundle, validate_invite_bundle
from .concord_invite_event import decode_invite_naddr, extract_invite_ciphertext
from .concord_transport import fetch_invite_events


class ConcordInviteError(ValueError):
    """An invite URL is malformed or missing its private fragment."""


@dataclass(frozen=True)
class InviteReference:
    """Public locator plus an opaque, secret fragment held only internally."""

    naddr: str
    fragment: str = field(repr=False)


@dataclass(frozen=True)
class InviteFragment:
    """Decoded bootstrap data; ``token`` remains secret internal state."""

    version: int
    relays: tuple[str, ...]
    token: bytes = field(repr=False)


_RELAY_DICTIONARY = {
    1: "wss://jskitty.com/nostr",
    2: "wss://asia.vectorapp.io/nostr",
    3: "wss://relay.ditto.pub",
    4: "wss://relay.dreamith.to",
}


def parse_invite_url(value: str, *, max_fragment_chars: int = 4096) -> InviteReference:
    """Parse ``<base>/invite/<naddr>#<fragment>`` without exposing secrets.

    The fragment is intentionally kept opaque here. CORD-05 owns its versioned
    encoding and bootstrap relay dictionary; a later decoder can consume it
    without making the MCP layer aware of the token.
    """

    if not isinstance(value, str) or not value:
        raise ConcordInviteError("invite URL must be a non-empty string")
    if max_fragment_chars <= 0:
        raise ValueError("max_fragment_chars must be positive")
    parsed = urlsplit(value)
    parts = parsed.path.rstrip("/").split("/")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConcordInviteError("invite URL must be an absolute HTTP(S) URL")
    if len(parts) < 2 or parts[-2] != "invite" or not parts[-1].startswith("naddr1"):
        raise ConcordInviteError("invite URL must contain an naddr after /invite/")
    if parsed.query:
        raise ConcordInviteError("invite URL must not contain a query string")
    if not parsed.fragment or len(parsed.fragment) > max_fragment_chars:
        raise ConcordInviteError("invite URL must contain a bounded fragment")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", parsed.fragment):
        raise ConcordInviteError("invite fragment must be unpadded base64url")
    return InviteReference(naddr=parts[-1], fragment=parsed.fragment)


def decode_invite_fragment(fragment: str, *, max_relays: int = 3) -> InviteFragment:
    """Decode the CORD-05 v4 fragment without logging or stringifying its token."""

    if not isinstance(fragment, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", fragment):
        raise ConcordInviteError("invite fragment must be unpadded base64url")
    if max_relays <= 0:
        raise ValueError("max_relays must be positive")
    try:
        raw = base64.urlsafe_b64decode(fragment + "=" * (-len(fragment) % 4))
    except (ValueError, TypeError) as exc:
        raise ConcordInviteError("invite fragment is not valid base64url") from exc
    if len(raw) < 18 or raw[0] != 4:
        raise ConcordInviteError("unsupported Concord invite fragment version")
    flags = raw[1]
    offset = 2
    relays: list[str] = []
    stock_relays = bool(flags & 1)
    if stock_relays:
        relays.extend(_RELAY_DICTIONARY.values())
    else:
        count = raw[offset]
        offset += 1
        if count > max_relays:
            raise ConcordInviteError("invite fragment contains too many bootstrap relays")
        for _ in range(count):
            if offset >= len(raw):
                raise ConcordInviteError("invite fragment relay data is truncated")
            relay_type = raw[offset]
            offset += 1
            if relay_type in _RELAY_DICTIONARY:
                relays.append(_RELAY_DICTIONARY[relay_type])
                continue
            if relay_type not in {0, 255} or offset >= len(raw):
                raise ConcordInviteError("invite fragment contains an unknown relay entry")
            length = raw[offset]
            offset += 1
            end = offset + length
            if end > len(raw):
                raise ConcordInviteError("invite fragment relay data is truncated")
            try:
                value = raw[offset:end].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ConcordInviteError("invite fragment relay is not UTF-8") from exc
            prefix = "wss://" if relay_type == 0 else ""
            relay = prefix + value
            if not relay.startswith(("wss://", "ws://")):
                raise ConcordInviteError("invite fragment relay must use ws(s)")
            relays.append(relay)
            offset = end
    if (not stock_relays and len(relays) > max_relays) or len(raw) - offset != 16:
        raise ConcordInviteError("invite fragment has invalid token or relay length")
    return InviteFragment(version=raw[0], relays=tuple(relays), token=raw[offset:])


def derive_invite_bundle_key(token: bytes) -> bytes:
    """Derive the CORD-05 bundle key from the 16-byte fragment token."""

    if not isinstance(token, bytes) or len(token) != 16:
        raise ConcordInviteError("invite token must be exactly 16 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"concord/invite-key").derive(token)


def decrypt_invite_bundle(ciphertext: str, token: bytes) -> ValidatedInviteBundle:
    """Decrypt and validate one fetched kind-33301 bundle.

    The caller is responsible for verifying the fetched event's addressable
    coordinate and signature before passing its content here. The token and
    derived key never appear in the returned bundle representation.
    """

    if not isinstance(ciphertext, str) or not ciphertext:
        raise ConcordInviteError("invite bundle ciphertext must be non-empty")
    try:
        bundle_key = derive_invite_bundle_key(token)
        secret = SecretKey.from_bytes(bundle_key)
        pubkey_hex = PublicKeyXOnly.from_valid_secret(bundle_key).format().hex()
        plaintext = nip44_decrypt(secret, PublicKey.parse(pubkey_hex), ciphertext)
        bundle = json.loads(plaintext)
        return validate_invite_bundle(bundle)
    except ConcordInviteError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize SDK/JSON failures
        raise ConcordInviteError("invite bundle decryption or validation failed") from exc


async def load_invite_bundle(
    invite_url: str,
    *,
    fetcher: Callable[[str, list[str]], Awaitable[list]] = fetch_invite_events,
) -> ValidatedInviteBundle:
    """Fetch, verify, decrypt, and validate a shareable invite bundle."""

    reference = parse_invite_url(invite_url)
    fragment = decode_invite_fragment(reference.fragment)
    coordinate = decode_invite_naddr(reference.naddr)
    if not fragment.relays:
        raise ConcordInviteError("invite fragment has no bootstrap relays")
    events = await fetcher(coordinate.author_hex, list(fragment.relays))
    if not events:
        raise ConcordInviteError("no invite bundle event was found")
    event = events[0]
    if hasattr(event, "as_json"):
        try:
            event = json.loads(event.as_json())
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ConcordInviteError("fetched invite event is not valid JSON") from exc
    if not isinstance(event, dict):
        raise ConcordInviteError("fetched invite event has an unsupported shape")
    ciphertext = extract_invite_ciphertext(event, expected_author=coordinate.author_hex)
    return decrypt_invite_bundle(ciphertext, fragment.token)
