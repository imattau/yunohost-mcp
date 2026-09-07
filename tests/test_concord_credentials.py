from pathlib import Path

import pytest

from coincurve import PrivateKey

from yunohost_mcp.concord_credentials import CredentialFileError, load_bot_private_key, read_credential_file


def _credential_file(tmp_path: Path, content: str = "secret-value") -> Path:
    path = tmp_path / "credential"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_read_credential_file_returns_value_without_transforming_content(tmp_path: Path):
    path = _credential_file(tmp_path, " npub-or-invite-value ")

    assert read_credential_file(path, label="Armada") == "npub-or-invite-value"


def test_read_credential_file_rejects_permissive_files(tmp_path: Path):
    path = _credential_file(tmp_path)
    path.chmod(0o640)

    with pytest.raises(CredentialFileError, match="group/world accessible"):
        read_credential_file(path, label="Armada")


def test_read_credential_file_rejects_multiline_or_oversized_values(tmp_path: Path):
    multiline = _credential_file(tmp_path, "first\nsecond")
    with pytest.raises(CredentialFileError, match="one non-empty value"):
        read_credential_file(multiline, label="Armada")

    oversized = _credential_file(tmp_path, "x" * 20)
    with pytest.raises(CredentialFileError, match="too large"):
        read_credential_file(oversized, label="Armada", max_bytes=8)


def test_read_credential_file_rejects_symlinks(tmp_path: Path):
    target = _credential_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(CredentialFileError, match="regular file"):
        read_credential_file(link, label="Armada")


def test_load_bot_private_key_parses_protected_hex_without_returning_text(tmp_path: Path):
    path = _credential_file(tmp_path, "a" * 64)

    key = load_bot_private_key(path)

    assert isinstance(key, PrivateKey)
    assert key.secret == bytes.fromhex("a" * 64)


def test_load_bot_private_key_hides_invalid_secret_details(tmp_path: Path):
    path = _credential_file(tmp_path, "not-a-private-key")

    with pytest.raises(CredentialFileError, match="not a valid private key") as error:
        load_bot_private_key(path)
    assert "not-a-private-key" not in str(error.value)
