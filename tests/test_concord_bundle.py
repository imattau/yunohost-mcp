import hashlib

import pytest

from yunohost_mcp.concord_bundle import ConcordBundleError, validate_invite_bundle


def _bundle():
    owner = "a" * 64
    salt = "b" * 64
    community_id = hashlib.sha256(b"concord/community" + bytes.fromhex(owner + salt)).hexdigest()
    return {
        "community_id": community_id,
        "owner": owner,
        "owner_salt": salt,
        "community_root": "c" * 64,
        "root_epoch": 2,
        "control_pk": "d" * 64,
        "relays": ["wss://relay.example"],
        "channels": [
            {"id": "e" * 64, "key": "f" * 64, "epoch": 1, "name": "ditto_ynh"},
            {"id": "0" * 64, "epoch": 2, "name": "general"},
        ],
    }


def test_validate_invite_bundle_checks_identity_and_hides_secrets():
    validated = validate_invite_bundle(_bundle())

    assert validated.community_id == _bundle()["community_id"]
    assert validated.channels[0].private is True
    assert validated.channels[1].private is False
    assert "c" * 64 not in repr(validated)
    assert "f" * 64 not in repr(validated)


def test_validate_invite_bundle_rejects_bad_identity_and_bounds():
    bundle = _bundle()
    bundle["community_id"] = "0" * 64
    with pytest.raises(ConcordBundleError, match="does not match"):
        validate_invite_bundle(bundle)

    bundle = _bundle()
    bundle["channels"] = [_bundle()["channels"][0]] * 257
    with pytest.raises(ConcordBundleError, match="channels"):
        validate_invite_bundle(bundle)


def test_validate_invite_bundle_rejects_malformed_channel_key():
    bundle = _bundle()
    bundle["channels"][0]["key"] = "not-hex"

    with pytest.raises(ConcordBundleError, match="channel key"):
        validate_invite_bundle(bundle)


def test_validate_invite_bundle_rejects_expired_invite():
    bundle = _bundle()
    bundle["expires_at"] = 1_000

    with pytest.raises(ConcordBundleError, match="expired"):
        validate_invite_bundle(bundle, now_ms=1_001)


def test_validate_invite_bundle_rejects_invalid_relay_and_duplicate_channel():
    bundle = _bundle()
    bundle["relays"] = ["https://relay.example"]
    with pytest.raises(ConcordBundleError, match="ws\\(s\\)"):
        validate_invite_bundle(bundle)

    bundle = _bundle()
    bundle["channels"].append(dict(bundle["channels"][0]))
    with pytest.raises(ConcordBundleError, match="duplicate"):
        validate_invite_bundle(bundle)
