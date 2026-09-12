import pytest
from nostr_sdk import Coordinate, Keys, Kind, Nip19Coordinate, PublicKey, SecretKey

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.concord_invite_event import ConcordInviteEventError, decode_invite_naddr, extract_invite_ciphertext


def _event(marker: str = "6"):
    key = Keys(SecretKey.from_bytes(b"i" * 32))
    author = key.public_key().to_hex()
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
    key = Keys(SecretKey.from_bytes(b"i" * 32))
    author = key.public_key().to_hex()
    naddr = Nip19Coordinate(Coordinate(Kind(33301), PublicKey.parse(author), "")).to_bech32()

    coordinate = decode_invite_naddr(naddr)

    assert coordinate.author_hex == author
    assert coordinate.kind == 33301
    assert coordinate.identifier == ""


def test_decode_invite_naddr_rejects_wrong_coordinate():
    naddr = Nip19Coordinate(Coordinate(Kind(1), PublicKey.parse(Keys.generate().public_key().to_hex()), "d")).to_bech32()

    with pytest.raises(ConcordInviteEventError, match="wrong coordinate"):
        decode_invite_naddr(naddr)
