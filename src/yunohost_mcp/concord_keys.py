"""CORD-02 deterministic group-key derivation primitives.

This module performs only local derivation. It does not load credential files,
publish events, or expose a key through an MCP response. The byte layout is
frozen by CORD-02: HKDF-SHA256 with an empty salt and
``label || NUL || id || epoch_be`` as info.
"""

from __future__ import annotations

from dataclasses import dataclass

from coincurve import PublicKeyXOnly
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class ConcordKeyError(ValueError):
    """Input cannot be used for a CORD key derivation."""


@dataclass(frozen=True)
class GroupKeyMaterial:
    """Derived CORD keypair material for an internal protocol adapter."""

    secret: bytes
    pubkey_hex: str


def _validate_inputs(secret: bytes, identifier: bytes, epoch: int | None) -> None:
    if len(secret) != 32:
        raise ConcordKeyError("CORD secret must be exactly 32 bytes")
    if len(identifier) != 32:
        raise ConcordKeyError("CORD identifier must be exactly 32 bytes")
    if epoch is not None and not 0 <= epoch <= 0xFFFFFFFFFFFFFFFF:
        raise ConcordKeyError("CORD epoch must fit an unsigned 64-bit integer")


def _derive_seed(secret: bytes, label: str, identifier: bytes, epoch: int | None, counter: int | None) -> bytes:
    info = label.encode("utf-8") + b"\x00" + identifier
    if epoch is not None:
        info += epoch.to_bytes(8, "big")
    if counter is not None:
        info += bytes([counter])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def derive_group_key(secret: bytes, label: str, identifier: bytes, epoch: int | None = 0) -> GroupKeyMaterial:
    """Derive a CORD group key and its x-only stream public key.

    CORD's scalar-normalize retry is included for completeness even though an
    invalid first seed is cryptographically negligible. The retry counter is
    appended to HKDF info, starting at zero.
    """

    _validate_inputs(secret, identifier, epoch)
    if not label:
        raise ConcordKeyError("CORD label must not be empty")
    for counter in [None, *range(256)]:
        seed = _derive_seed(secret, label, identifier, epoch, counter)
        scalar = int.from_bytes(seed, "big")
        if 0 < scalar < _CURVE_ORDER:
            return GroupKeyMaterial(
                secret=seed,
                pubkey_hex=PublicKeyXOnly.from_valid_secret(seed).format().hex(),
            )
    raise ConcordKeyError("CORD scalar normalization exhausted its retry counter")
