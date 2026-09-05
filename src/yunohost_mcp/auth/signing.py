"""Client-side NIP-98 signing - the counterpart to nip98.py's server-side
verification. Used by bridge.py to let a mainstream MCP client (which has
no idea what Nostr is) talk to a yunohost-mcp server, which authenticates
every request with it.

This is the one place in the codebase that handles a *private* key deriving
from user input, not the server generating and keeping its own (see
auth/server_identity.py's own docstring on that distinction) - it exists
because a client signing its own requests necessarily needs its own key
locally, the same as any Nostr client does; PLAN.md Phase 9's "never store
users' nsec keys" is about the *server* never holding someone else's key,
not about a client being unable to hold its own.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from coincurve import PrivateKey, PublicKeyXOnly

from yunohost_mcp.auth.nip98 import NIP98_KIND
from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.auth.npub import Bech32Error, hex_to_npub, nsec_to_hex


class KeyLoadError(ValueError):
    """A supplied key string is neither valid hex nor a valid nsec."""


@dataclass(frozen=True)
class ClientIdentity:
    """A locally-held Nostr keypair used to sign outgoing requests."""

    private_key: PrivateKey
    pubkey_hex: str

    @property
    def npub(self) -> str:
        return hex_to_npub(self.pubkey_hex)

    @classmethod
    def from_key_string(cls, key: str) -> ClientIdentity:
        """Accepts a raw 64-char hex private key or an nsec1... bech32 string."""
        key = key.strip()
        if key.startswith("nsec1"):
            try:
                hex_key = nsec_to_hex(key)
            except Bech32Error as exc:
                raise KeyLoadError(str(exc)) from exc
        else:
            hex_key = key

        try:
            private_key = PrivateKey(bytes.fromhex(hex_key))
        except (ValueError, TypeError) as exc:
            raise KeyLoadError(f"not a valid hex or nsec private key: {exc}") from exc

        pubkey_hex = PublicKeyXOnly.from_valid_secret(private_key.secret).format().hex()
        return cls(private_key=private_key, pubkey_hex=pubkey_hex)

    def sign_nip98(self, *, method: str, url: str, body: bytes = b"") -> str:
        """Return a complete 'Nostr <base64>' Authorization header value
        for one exact request (method, absolute url, body) - a fresh event
        is signed every call, per NIP-98; nothing here is reusable across
        requests, by design (see auth/nip98.py's replay protection).

        `created_at` only has 1-second resolution, and NIP-98 otherwise
        binds nothing but method/url/payload - so two *independent* calls
        here for the same request shape within the same wall-clock second
        would otherwise produce byte-identical events (same id), and the
        server's replay cache would reject the second one even though it
        is not a replay at all. This matters in practice: a long-running
        tool call's SSE stream can reconnect more than once within a
        second, each reconnection legitimately re-signing the same GET
        method/url. A random nonce tag makes every call's event unique
        regardless of timing, while an actual reused header (the same
        signed event sent twice) still collides and is still rejected -
        the server ignores unrecognized tags, so this is invisible to it.
        """
        tags = [["u", url], ["method", method.upper()], ["nonce", secrets.token_hex(16)]]
        if body:
            tags.append(["payload", hashlib.sha256(body).hexdigest()])
        event = sign_event(
            self.private_key, pubkey=self.pubkey_hex, kind=NIP98_KIND, tags=tags, created_at=int(time.time())
        )
        encoded = base64.b64encode(json.dumps(event.model_dump()).encode()).decode()
        return f"Nostr {encoded}"
