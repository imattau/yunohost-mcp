from __future__ import annotations

import stat
from pathlib import Path

import pytest

from yunohost_mcp.auth.server_identity import ServerIdentity, ServerIdentityError


def test_generates_new_identity_on_first_load(tmp_path: Path):
    path = tmp_path / "server_identity.key"
    identity = ServerIdentity.load_or_generate(path)
    assert path.exists()
    assert len(identity.pubkey_hex) == 64
    assert identity.npub.startswith("npub1")


def test_file_is_written_with_owner_only_permissions(tmp_path: Path):
    path = tmp_path / "server_identity.key"
    ServerIdentity.load_or_generate(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR


def test_reloads_same_identity_on_second_call(tmp_path: Path):
    path = tmp_path / "server_identity.key"
    first = ServerIdentity.load_or_generate(path)
    second = ServerIdentity.load_or_generate(path)
    assert first.pubkey_hex == second.pubkey_hex
    assert first.npub == second.npub


def test_rejects_group_readable_file(tmp_path: Path):
    path = tmp_path / "server_identity.key"
    ServerIdentity.load_or_generate(path)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    with pytest.raises(ServerIdentityError, match="group or others"):
        ServerIdentity.load_or_generate(path)


def test_rejects_malformed_key_file(tmp_path: Path):
    path = tmp_path / "server_identity.key"
    path.write_text("not a valid hex key")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with pytest.raises(ServerIdentityError):
        ServerIdentity.load_or_generate(path)


def test_sign_produces_a_verifiable_schnorr_signature(tmp_path: Path):
    from coincurve import PublicKeyXOnly

    path = tmp_path / "server_identity.key"
    identity = ServerIdentity.load_or_generate(path)
    message = b"\x00" * 32
    sig = identity.sign(message)
    pubkey = PublicKeyXOnly(bytes.fromhex(identity.pubkey_hex))
    assert pubkey.verify(sig, message)
