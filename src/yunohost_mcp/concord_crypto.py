"""NIP-44 primitives used by the Concord envelope adapter."""

from __future__ import annotations

from collections.abc import Callable

from nostr_sdk import Nip44Version, PublicKey, SecretKey, nip44_decrypt, nip44_encrypt

from .concord_keys import GroupKeyMaterial


class ConcordCryptoError(ValueError):
    """Invalid key material or unsupported Concord crypto operation."""


def self_conversation_encryptor(stream_key: GroupKeyMaterial) -> Callable[[str], str]:
    """Return a NIP-44 v2 encryptor for a Concord stream's self-ECDH key.

    CORD-02 defines the stream conversation key as NIP-44 self-ECDH using the
    derived stream secret and its x-only public key. The returned closure keeps
    those parsed key objects local and exposes only ciphertext to its caller.
    """

    try:
        secret_key = SecretKey.from_bytes(stream_key.secret)
        public_key = PublicKey.parse(stream_key.pubkey_hex)
    except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
        raise ConcordCryptoError("invalid Concord stream key material") from exc

    def encrypt(content: str) -> str:
        if not isinstance(content, str):
            raise TypeError("NIP-44 content must be text")
        try:
            return nip44_encrypt(secret_key, public_key, content, Nip44Version.V2)
        except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
            raise ConcordCryptoError("NIP-44 encryption failed") from exc

    return encrypt


def decrypt_self_conversation(stream_key: GroupKeyMaterial, payload: str) -> str:
    """Decrypt one NIP-44 payload addressed to a derived stream key."""

    try:
        secret_key = SecretKey.from_bytes(stream_key.secret)
        public_key = PublicKey.parse(stream_key.pubkey_hex)
        return nip44_decrypt(secret_key, public_key, payload)
    except Exception as exc:  # noqa: BLE001 - normalize SDK-specific errors
        raise ConcordCryptoError("NIP-44 decryption failed") from exc
