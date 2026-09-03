from __future__ import annotations

import pytest

from yunohost_mcp.auth.nip98 import verify_nip98_request
from yunohost_mcp.auth.npub import hex_to_nsec
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.signing import ClientIdentity, KeyLoadError


def test_from_key_string_accepts_raw_hex():
    hex_key = "8" * 64
    identity = ClientIdentity.from_key_string(hex_key)
    assert len(identity.pubkey_hex) == 64
    assert identity.npub.startswith("npub1")


def test_from_key_string_accepts_nsec():
    hex_key = "9" * 64
    nsec = hex_to_nsec(hex_key)
    identity = ClientIdentity.from_key_string(nsec)
    from_hex = ClientIdentity.from_key_string(hex_key)
    assert identity.pubkey_hex == from_hex.pubkey_hex


def test_from_key_string_strips_whitespace():
    hex_key = "7" * 64
    identity = ClientIdentity.from_key_string(f"  {hex_key}\n")
    assert identity.pubkey_hex == ClientIdentity.from_key_string(hex_key).pubkey_hex


def test_from_key_string_rejects_garbage():
    with pytest.raises(KeyLoadError):
        ClientIdentity.from_key_string("not-a-key")


def test_from_key_string_rejects_malformed_nsec():
    with pytest.raises(KeyLoadError):
        ClientIdentity.from_key_string("nsec1notreallybech32")


def test_sign_nip98_produces_a_header_the_server_side_verifier_accepts():
    identity = ClientIdentity.from_key_string("1" * 64)
    url = "https://mcp.example.com/mcp"
    header = identity.sign_nip98(method="GET", url=url)

    verified = verify_nip98_request(
        authorization_header=header, method="GET", url=url, body=b"", replay_cache=ReplayCache()
    )
    assert verified.pubkey == identity.pubkey_hex


def test_sign_nip98_binds_the_payload_hash_for_a_body():
    identity = ClientIdentity.from_key_string("2" * 64)
    url = "https://mcp.example.com/mcp"
    body = b'{"jsonrpc":"2.0","method":"tools/list"}'
    header = identity.sign_nip98(method="POST", url=url, body=body)

    verified = verify_nip98_request(
        authorization_header=header, method="POST", url=url, body=body, replay_cache=ReplayCache()
    )
    assert verified.pubkey == identity.pubkey_hex

    # Tampering with the body after the fact must be rejected.
    from yunohost_mcp.auth.nip98 import Nip98Error

    with pytest.raises(Nip98Error, match="payload"):
        verify_nip98_request(
            authorization_header=header, method="POST", url=url, body=b"tampered", replay_cache=ReplayCache()
        )


def test_signed_header_cannot_be_reused_across_requests():
    # Two calls to sign_nip98() within the same wall-clock second produce
    # byte-identical events (created_at has 1-second resolution) - proves
    # the *server's* replay protection correctly treats a resent header as
    # a replay rather than a coincidentally-fresh second signature, which
    # is the real-world failure mode a bridge reusing a header would hit.
    identity = ClientIdentity.from_key_string("3" * 64)
    url = "https://mcp.example.com/mcp"
    header = identity.sign_nip98(method="GET", url=url)
    cache = ReplayCache()
    verify_nip98_request(authorization_header=header, method="GET", url=url, body=b"", replay_cache=cache)

    from yunohost_mcp.auth.nip98 import Nip98Error

    with pytest.raises(Nip98Error, match="already used"):
        verify_nip98_request(authorization_header=header, method="GET", url=url, body=b"", replay_cache=cache)
