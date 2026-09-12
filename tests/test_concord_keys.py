import pytest

from nostr_sdk import Keys, SecretKey

from yunohost_mcp.concord_keys import ConcordKeyError, derive_group_key


def test_group_key_is_deterministic_and_x_only():
    secret = bytes(range(32))
    identifier = bytes(reversed(range(32)))

    first = derive_group_key(secret, "concord/channel", identifier, 3)
    second = derive_group_key(secret, "concord/channel", identifier, 3)

    assert first == second
    assert len(first.secret) == 32
    assert len(first.pubkey_hex) == 64
    assert Keys(SecretKey.from_bytes(first.secret)).public_key().to_hex() == first.pubkey_hex


def test_group_key_changes_with_channel_or_epoch():
    secret = b"s" * 32
    channel = b"c" * 32

    first = derive_group_key(secret, "concord/channel", channel, 0)
    other_channel = derive_group_key(secret, "concord/channel", b"d" * 32, 0)
    other_epoch = derive_group_key(secret, "concord/channel", channel, 1)

    assert first.pubkey_hex not in {other_channel.pubkey_hex, other_epoch.pubkey_hex}


@pytest.mark.parametrize(
    "secret, identifier, epoch",
    [(b"short", b"i" * 32, 0), (b"s" * 32, b"short", 0), (b"s" * 32, b"i" * 32, -1)],
)
def test_group_key_validates_protocol_dimensions(secret, identifier, epoch):
    with pytest.raises(ConcordKeyError):
        derive_group_key(secret, "concord/channel", identifier, epoch)
