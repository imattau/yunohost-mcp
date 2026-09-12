"""Guarded loading of file-backed Concord bot credentials.

The returned value is intended for immediate use by a protocol adapter. Callers
must not log it or include it in MCP responses.
"""

from __future__ import annotations

import os
from pathlib import Path

from nostr_sdk import Keys

from .auth.signing import ClientIdentity


class CredentialFileError(ValueError):
    """A configured credential file is missing, unsafe, or malformed."""


def load_bot_private_key(path: Path) -> Keys:
    """Load a protected bot nsec/hex credential without exposing its value."""

    try:
        value = read_credential_file(path, label="Concord bot")
        return ClientIdentity.from_key_string(value).private_key
    except CredentialFileError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize key parser errors
        raise CredentialFileError("Concord bot credential is not a valid private key") from exc


def read_credential_file(path: Path, *, label: str, max_bytes: int = 16_384) -> str:
    """Read one protected, non-empty, single-value credential file.

    Root-owned files are allowed because the production MCP service normally
    runs with root privileges on YunoHost.  Group/world-readable files are
    rejected, as are symlinks and files owned by an unrelated user.
    """

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    try:
        stat = path.lstat()
    except OSError as exc:
        raise CredentialFileError(f"{label} credential file is unavailable") from exc
    if not path.is_file() or path.is_symlink():
        raise CredentialFileError(f"{label} credential path must be a regular file")
    if stat.st_mode & 0o077:
        raise CredentialFileError(f"{label} credential file must not be group/world accessible")
    if stat.st_uid not in {0, os.getuid()}:
        raise CredentialFileError(f"{label} credential file has an unexpected owner")
    if stat.st_size > max_bytes:
        raise CredentialFileError(f"{label} credential file is too large")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise CredentialFileError(f"{label} credential file cannot be read") from exc
    if not value or "\n" in value or "\r" in value:
        raise CredentialFileError(f"{label} credential file must contain one non-empty value")
    return value
