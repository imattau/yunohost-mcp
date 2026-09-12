"""NIP-19 bech32 <-> hex conversions for Nostr keys.

Identity config (identity.toml) is keyed by npub for human readability
(matching PLAN.md's example), but NIP-98 events and everything downstream
use raw hex pubkeys — npub_to_hex/hex_to_npub bridge the two.

nsec_to_hex/hex_to_nsec do the same for *private* keys, used only by the
client-side signing bridge (bridge.py) reading a caller-supplied nsec to
sign outgoing requests with - never by the server side, which only ever
handles public keys (see PLAN.md Phase 9: "private Nostr keys must never
be stored by yunohost-mcp" - that's about the server; a client signing its
own requests necessarily holds its own key locally, same as any Nostr
client).

Delegates to nostr-sdk's own bech32 handling rather than a hand-rolled
implementation.
"""

from __future__ import annotations

from nostr_sdk import PublicKey, SecretKey

NPUB_HRP = "npub"
NSEC_HRP = "nsec"


class Bech32Error(ValueError):
    """A bech32 Nostr key string is malformed or the wrong kind (npub vs nsec)."""


def _public_key(value: str, *, expected_hrp: str) -> PublicKey:
    # PublicKey.parse() also accepts raw hex and nostr: URIs - reject those
    # explicitly so a caller that means to decode a UI-supplied npub can't
    # silently succeed on the wrong kind of input.
    if not value.startswith(f"{expected_hrp}1"):
        raise Bech32Error(f"not a valid {expected_hrp}: {value!r}")
    try:
        return PublicKey.parse(value)
    except Exception as exc:  # noqa: BLE001 - normalize rust-nostr parse errors
        raise Bech32Error(f"not a valid {expected_hrp}: {value!r}") from exc


def _secret_key(value: str, *, expected_hrp: str) -> SecretKey:
    if not value.startswith(f"{expected_hrp}1"):
        raise Bech32Error(f"not a valid {expected_hrp}: {value!r}")
    try:
        return SecretKey.parse(value)
    except Exception as exc:  # noqa: BLE001 - normalize rust-nostr parse errors
        raise Bech32Error(f"not a valid {expected_hrp}: {value!r}") from exc


def npub_to_hex(npub: str) -> str:
    return _public_key(npub, expected_hrp=NPUB_HRP).to_hex()


def hex_to_npub(pubkey_hex: str) -> str:
    try:
        return PublicKey.parse(pubkey_hex).to_bech32()
    except Exception as exc:  # noqa: BLE001 - normalize rust-nostr parse errors
        raise Bech32Error(f"not a valid hex pubkey: {pubkey_hex!r}") from exc


def nsec_to_hex(nsec: str) -> str:
    return _secret_key(nsec, expected_hrp=NSEC_HRP).to_hex()


def hex_to_nsec(privkey_hex: str) -> str:
    try:
        return SecretKey.parse(privkey_hex).to_bech32()
    except Exception as exc:  # noqa: BLE001 - normalize rust-nostr parse errors
        raise Bech32Error(f"not a valid hex private key: {privkey_hex!r}") from exc
