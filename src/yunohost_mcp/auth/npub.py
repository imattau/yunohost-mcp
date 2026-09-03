"""NIP-19 npub <-> hex pubkey conversion.

Identity config (identity.toml) is keyed by npub for human readability
(matching PLAN.md's example), but NIP-98 events and everything downstream
use raw hex pubkeys — this is the one place that bridges the two.
"""

from __future__ import annotations

import bech32

NPUB_HRP = "npub"


class Bech32Error(ValueError):
    """An npub string is malformed or not a valid NIP-19 npub."""


def npub_to_hex(npub: str) -> str:
    hrp, data = bech32.bech32_decode(npub)
    if hrp != NPUB_HRP or data is None:
        raise Bech32Error(f"not a valid npub: {npub!r}")
    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) != 32:
        raise Bech32Error(f"npub does not decode to a 32-byte pubkey: {npub!r}")
    return bytes(decoded).hex()


def hex_to_npub(pubkey_hex: str) -> str:
    raw = bytes.fromhex(pubkey_hex)
    if len(raw) != 32:
        raise Bech32Error(f"expected 32-byte hex pubkey, got {len(raw)} bytes")
    data = bech32.convertbits(raw, 8, 5, True)
    if data is None:
        raise Bech32Error(f"failed to convert pubkey to bech32 data: {pubkey_hex!r}")
    return bech32.bech32_encode(NPUB_HRP, data)
