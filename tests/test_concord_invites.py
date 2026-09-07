import pytest
import base64
import hashlib
import json

import bech32
from nostr_sdk import Nip44Version, PublicKey, SecretKey, nip44_encrypt
from coincurve import PrivateKey, PublicKeyXOnly

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
        "wss://relay.ditto.pub",
        "wss://relay.dreamith.to",
    )
    assert decoded.token == b"t" * 16
    assert "tttt" not in repr(decoded)


def test_decode_invite_fragment_handles_bounded_custom_relays():
    raw = bytes([4, 0, 2, 3, 255, len(b"ws://localhost:8080")]) + b"ws://localhost:8080" + b"k" * 16
    fragment = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    decoded = decode_invite_fragment(fragment)

    assert decoded.relays == ("wss://relay.ditto.pub", "ws://localhost:8080")


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
    secret = SecretKey.from_bytes(key)
    pubkey = PublicKey.parse(PublicKeyXOnly.from_valid_secret(key).format().hex())
    ciphertext = nip44_encrypt(
        secret,
        pubkey,
        json.dumps(bundle, separators=(",", ":")),
        Nip44Version.V2,
    )

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
    ciphertext = nip44_encrypt(
        SecretKey.from_bytes(bundle_key),
        PublicKey.parse(PublicKeyXOnly.from_valid_secret(bundle_key).format().hex()),
        json.dumps(bundle, separators=(",", ":")),
        Nip44Version.V2,
    )
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
