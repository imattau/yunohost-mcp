"""This server's own Nostr identity (PLAN.md Phase 12, minimal slice).

Distinct from every *user*/*agent* identity this codebase deals with:
this is a keypair the server itself generates and controls, analogous to
a TLS certificate's private key - infrastructure key material, not a
borrowed or delegated credential. PLAN.md Phase 9's "never store users'
nsec keys" is about *other people's* keys; a server signing its own
receipts with its own key is what Phase 12 explicitly asks for.

Used for (this slice): letting a delegation (auth/delegation.py, Phase 11)
name which server it targets, and letting a caller ask which server
they're talking to (server.py's server_identity tool). Signing operation
receipts / health reports with it is later Phase 12 work, not built yet -
`sign()` exists now because delegation targeting needs *a* server identity
to exist, and a keypair that can't sign isn't one.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.npub import hex_to_npub


class ServerIdentityError(RuntimeError):
    """The server identity key file is missing, unreadable, or has unsafe permissions."""


@dataclass(frozen=True)
class ServerIdentity:
    _private_key: PrivateKey
    pubkey_hex: str

    @property
    def npub(self) -> str:
        return hex_to_npub(self.pubkey_hex)

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign_schnorr(message)

    @classmethod
    def load_or_generate(cls, path: Path) -> ServerIdentity:
        """Load the server's keypair from `path`, generating and persisting
        a new one on first run. The file holds nothing but 64 hex chars (32
        raw bytes) - the private key, and only the private key; the public
        key/npub are always re-derived, never stored redundantly."""
        if path.exists():
            _assert_private_permissions(path)
            secret_hex = path.read_text().strip()
            try:
                private_key = PrivateKey(bytes.fromhex(secret_hex))
            except (ValueError, TypeError) as exc:
                raise ServerIdentityError(f"{path}: not a valid 32-byte hex private key") from exc
        else:
            private_key = PrivateKey()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(private_key.to_hex())
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600: owner read/write only

        pubkey_hex = PublicKeyXOnly.from_valid_secret(private_key.secret).format().hex()
        return cls(_private_key=private_key, pubkey_hex=pubkey_hex)


def _assert_private_permissions(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ServerIdentityError(
            f"{path} is readable/writable by group or others (mode {oct(mode)}) - "
            "this file holds this server's private key; chmod 600 it before continuing"
        )
