from __future__ import annotations

import pytest

from yunohost_mcp.auth.npub import Bech32Error, hex_to_npub, hex_to_nsec, npub_to_hex


def test_roundtrip():
    hex_pubkey = "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"
    npub = hex_to_npub(hex_pubkey)
    assert npub.startswith("npub1")
    assert npub_to_hex(npub) == hex_pubkey


def test_invalid_npub_rejected():
    with pytest.raises(Bech32Error):
        npub_to_hex("npub1notavalidbech32string")


def test_wrong_hrp_rejected():
    # A valid bech32 string, but with the wrong human-readable prefix.
    fake = hex_to_nsec("11" * 32)
    with pytest.raises(Bech32Error):
        npub_to_hex(fake)
