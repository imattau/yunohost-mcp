import pytest
import bech32
from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.concord_invite_event import ConcordInviteEventError, decode_invite_naddr, extract_invite_ciphertext


def _event(marker: str = "6"):
    key = PrivateKey(b"i" * 32)
    author = PublicKeyXOnly.from_valid_secret(key.secret).format().hex()
    return sign_event(
        key,
        pubkey=author,
        kind=33301,
        tags=[["d", ""], ["vsk", marker]],
        content="encrypted-bundle",
        created_at=1,
    ).model_dump(), author


def test_extract_invite_ciphertext_verifies_live_coordinate():
    event, author = _event()

    assert extract_invite_ciphertext(event, expected_author=author) == "encrypted-bundle"


@pytest.mark.parametrize("marker, message", [("9", "revoked"), ("2", "live")])
def test_extract_invite_ciphertext_rejects_non_live_markers(marker, message):
    event, author = _event(marker)

    with pytest.raises(ConcordInviteEventError, match=message):
        extract_invite_ciphertext(event, expected_author=author)


def test_extract_invite_ciphertext_rejects_wrong_author():
    event, _ = _event()

    with pytest.raises(ConcordInviteEventError, match="unexpected"):
        extract_invite_ciphertext(event, expected_author="0" * 64)


def test_decode_invite_naddr_extracts_the_link_signer_coordinate():
    key = PrivateKey(b"i" * 32)
    author = PublicKeyXOnly.from_valid_secret(key.secret).format()
    raw = bytes([0, 0, 2, 32]) + author + bytes([3, 4]) + (33301).to_bytes(4, "big")
    naddr = bech32.bech32_encode("naddr", bech32.convertbits(raw, 8, 5, True))

    coordinate = decode_invite_naddr(naddr)

    assert coordinate.author_hex == author.hex()
    assert coordinate.kind == 33301
    assert coordinate.identifier == ""


def test_decode_invite_naddr_rejects_wrong_coordinate():
    raw = bytes([0, 1]) + b"d" + bytes([2, 32]) + b"a" * 32 + bytes([3, 4]) + (1).to_bytes(4, "big")
    naddr = bech32.bech32_encode("naddr", bech32.convertbits(raw, 8, 5, True))

    with pytest.raises(ConcordInviteEventError, match="wrong coordinate"):
        decode_invite_naddr(naddr)
