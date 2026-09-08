import pytest
import base64
import hmac
import hashlib
import json

import bech32
from coincurve import PrivateKey, PublicKeyXOnly
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.concord_invites import (
    ConcordInviteError,
    InviteReference,
    decode_invite_fragment,
    decrypt_invite_bundle,
    derive_invite_bundle_key,
    load_invite_bundle,
    parse_invite_url,
)


def _raw_nip44_encrypt(plaintext: str, key: bytes) -> str:
    nonce = b"n" * 32
    raw = plaintext.encode()
    padded = len(raw).to_bytes(2, "big") + raw
    if len(raw) <= 32:
        padded_len = 32
    else:
        next_power = 1 << (len(raw) - 1).bit_length()
        chunk = 32 if next_power <= 256 else next_power // 8
        padded_len = chunk * ((len(raw) - 1) // chunk + 1)
    padded += b"\x00" * (padded_len - len(raw))
    expanded = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce).derive(key)
    chacha_key, chacha_nonce, hmac_key = expanded[:32], expanded[32:44], expanded[44:]
    encryptor = Cipher(algorithms.ChaCha20(chacha_key, b"\x00" * 4 + chacha_nonce), mode=None).encryptor()
    body = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(hmac_key, nonce + body, "sha256").digest()
    return base64.b64encode(b"\x02" + nonce + body + mac).decode()


def test_parse_invite_url_keeps_locator_and_opaque_fragment():
    parsed = parse_invite_url("https://armada.example/invite/naddr1example#v4-token")

    assert parsed == InviteReference(naddr="naddr1example", fragment="v4-token")
    assert "v4-token" not in repr(parsed)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "armada.example/invite/naddr1example#token",
        "https://armada.example/join/naddr1example#token",
        "https://armada.example/invite/naddr1example",
        "https://armada.example/invite/naddr1example#token?query",
    ],
)
def test_parse_invite_url_rejects_malformed_or_secret_leaking_shapes(value):
    with pytest.raises(ConcordInviteError):
        parse_invite_url(value)


def test_decode_invite_fragment_expands_stock_relays_without_repr_token():
    raw = bytes([4, 1]) + b"t" * 16
    fragment = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    decoded = decode_invite_fragment(fragment)

    assert decoded.version == 4
    assert decoded.relays == (
        "wss://jskitty.com/nostr",
        "wss://asia.vectorapp.io/nostr",
        "wss://nostr.computingcache.com",
        "wss://relay.damus.io",
    )
    assert decoded.token == b"t" * 16
    assert "tttt" not in repr(decoded)


def test_decode_invite_fragment_handles_bounded_custom_relays():
    raw = bytes([4, 0, 2, 3, 255, len(b"ws://localhost:8080")]) + b"ws://localhost:8080" + b"k" * 16
    fragment = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    decoded = decode_invite_fragment(fragment)

    assert decoded.relays == ("wss://nostr.computingcache.com", "ws://localhost:8080")


def test_decode_invite_fragment_rejects_version_and_size_errors():
    for raw in (bytes([3, 1]) + b"t" * 16, bytes([4, 0, 4]) + b"t" * 16):
        fragment = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        with pytest.raises(ConcordInviteError):
            decode_invite_fragment(fragment)


def test_decrypt_invite_bundle_derives_token_key_and_validates_bundle():
    token = b"t" * 16
    owner = "a" * 64
    salt = "b" * 64
    bundle = {
        "community_id": hashlib.sha256(b"concord/community" + bytes.fromhex(owner + salt)).hexdigest(),
        "owner": owner,
        "owner_salt": salt,
        "community_root": "c" * 64,
        "root_epoch": 2,
        "control_pk": "d" * 64,
        "relays": ["wss://relay.example"],
        "channels": [{"id": "e" * 64, "epoch": 1, "name": "ditto_ynh"}],
    }
    key = derive_invite_bundle_key(token)
    ciphertext = _raw_nip44_encrypt(json.dumps(bundle, separators=(",", ":")), key)

    decoded = decrypt_invite_bundle(ciphertext, token)

    assert decoded.community_id == bundle["community_id"]


def test_decrypt_invite_bundle_rejects_wrong_token():
    with pytest.raises(ConcordInviteError, match="decryption"):
        decrypt_invite_bundle("not-ciphertext", b"t" * 16)


@pytest.mark.anyio
async def test_load_invite_bundle_composes_fetch_verify_and_decrypt():
    token = b"t" * 16
    owner = "a" * 64
    salt = "b" * 64
    bundle = {
        "community_id": hashlib.sha256(b"concord/community" + bytes.fromhex(owner + salt)).hexdigest(),
        "owner": owner,
        "owner_salt": salt,
        "community_root": "c" * 64,
        "root_epoch": 2,
        "control_pk": "d" * 64,
        "relays": ["wss://relay.example"],
        "channels": [{"id": "e" * 64, "epoch": 1, "name": "ditto_ynh"}],
    }
    link_pubkey = PublicKeyXOnly.from_valid_secret(b"i" * 32).format().hex()
    bundle_key = derive_invite_bundle_key(token)
    ciphertext = _raw_nip44_encrypt(json.dumps(bundle, separators=(",", ":")), bundle_key)
    event = sign_event(
        PrivateKey(b"i" * 32),
        pubkey=link_pubkey,
        kind=33301,
        tags=[["d", ""], ["vsk", "6"]],
        content=ciphertext,
        created_at=1,
    ).model_dump()
    raw = bytes([4, 1]) + token
    fragment = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    author = bytes.fromhex(link_pubkey)
    naddr_raw = bytes([0, 0, 2, 32]) + author + bytes([3, 4]) + (33301).to_bytes(4, "big")
    naddr = bech32.bech32_encode("naddr", bech32.convertbits(naddr_raw, 8, 5, True))

    async def fetcher(author_hex, relays):
        assert author_hex == link_pubkey
        assert relays
        return [event]

    loaded = await load_invite_bundle(f"https://armada.example/invite/{naddr}#{fragment}", fetcher=fetcher)

    assert loaded.community_id == bundle["community_id"]
