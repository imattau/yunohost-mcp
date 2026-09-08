"""Safe parsing of Concord shareable invite references."""

from __future__ import annotations

from dataclasses import dataclass, field
import base64
import hmac
import json
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

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
    3: "wss://nostr.computingcache.com",
    4: "wss://relay.damus.io",
}

_ZERO32 = b"\x00" * 32


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
    """Derive the CORD-05 bundle key from the 16-byte fragment token.

    CORD-05 uses the frozen Concord derivation shape: ``label || NUL ||
    zero-community-id``.  The bundle is then encrypted with this raw key,
    rather than an ECDH-derived NIP-44 conversation.
    """

    if not isinstance(token, bytes) or len(token) != 16:
        raise ConcordInviteError("invite token must be exactly 16 bytes")
    info = b"concord/invite-key\x00" + _ZERO32
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=info).derive(token)


def _decrypt_raw_nip44(ciphertext: str, conversation_key: bytes) -> str:
    """Open a NIP-44 v2 payload using a raw 32-byte conversation key.

    This is the symmetric form used by Armada/Vector for public invite
    bundles.  ``nostr_sdk.nip44_decrypt`` only accepts the ECDH keypair form.
    """

    raw = base64.b64decode(ciphertext, validate=True)
    if len(raw) < 1 + 32 + 2 + 32 or raw[0] != 2:
        raise ValueError("invalid NIP-44 payload")
    nonce = raw[1:33]
    body, mac = raw[33:-32], raw[-32:]
    expanded = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce).derive(conversation_key)
    chacha_key, chacha_nonce, hmac_key = expanded[:32], expanded[32:44], expanded[44:]
    expected_mac = hmac.new(hmac_key, nonce + body, "sha256").digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("NIP-44 payload authentication failed")
    decryptor = Cipher(algorithms.ChaCha20(chacha_key, b"\x00" * 4 + chacha_nonce), mode=None).decryptor()
    padded = decryptor.update(body) + decryptor.finalize()
    if len(padded) < 2:
        raise ValueError("invalid NIP-44 padding")
    length = int.from_bytes(padded[:2], "big")
    if length == 0 or length > len(padded) - 2:
        raise ValueError("invalid NIP-44 padding")
    if length <= 32:
        padded_len = 32
    else:
        next_power = 1 << (length - 1).bit_length()
        chunk = 32 if next_power <= 256 else next_power // 8
        padded_len = chunk * ((length - 1) // chunk + 1)
    if len(padded) != 2 + padded_len:
        raise ValueError("invalid NIP-44 padding")
    return padded[2 : 2 + length].decode("utf-8")


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
        plaintext = _decrypt_raw_nip44(ciphertext, bundle_key)
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
