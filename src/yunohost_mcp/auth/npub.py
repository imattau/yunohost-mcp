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
"""

from __future__ import annotations

import bech32

NPUB_HRP = "npub"
NSEC_HRP = "nsec"


class Bech32Error(ValueError):
    """A bech32 Nostr key string is malformed or the wrong kind (npub vs nsec)."""


def _bech32_to_32_bytes(value: str, *, expected_hrp: str) -> bytes:
    hrp, data = bech32.bech32_decode(value)
    if hrp != expected_hrp or data is None:
        raise Bech32Error(f"not a valid {expected_hrp}: {value!r}")
    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) != 32:
        raise Bech32Error(f"{expected_hrp} does not decode to 32 bytes: {value!r}")
    return bytes(decoded)


def _32_bytes_to_bech32(raw: bytes, *, hrp: str) -> str:
    if len(raw) != 32:
        raise Bech32Error(f"expected 32 raw bytes, got {len(raw)}")
    data = bech32.convertbits(raw, 8, 5, True)
    if data is None:
        raise Bech32Error(f"failed to convert to bech32 data (hrp={hrp!r})")
    return bech32.bech32_encode(hrp, data)


def npub_to_hex(npub: str) -> str:
    return _bech32_to_32_bytes(npub, expected_hrp=NPUB_HRP).hex()


def hex_to_npub(pubkey_hex: str) -> str:
    return _32_bytes_to_bech32(bytes.fromhex(pubkey_hex), hrp=NPUB_HRP)


def nsec_to_hex(nsec: str) -> str:
    return _bech32_to_32_bytes(nsec, expected_hrp=NSEC_HRP).hex()


def hex_to_nsec(privkey_hex: str) -> str:
    return _32_bytes_to_bech32(bytes.fromhex(privkey_hex), hrp=NSEC_HRP)
