"""Request-scoped access to the authenticated caller's identity.

The NIP-98 middleware sets this once per HTTP request, before the MCP
session handles it. Tool handlers, the (future) policy engine, and the
audit log all read the same contextvar so there is exactly one notion of
"who is making this call" per request.
"""

from __future__ import annotations

from contextvars import ContextVar

from yunohost_mcp.auth.nip98 import Nip98Identity

_current_identity: ContextVar[Nip98Identity | None] = ContextVar("current_identity", default=None)


def set_current_identity(identity: Nip98Identity | None) -> None:
    _current_identity.set(identity)


def get_current_identity() -> Nip98Identity | None:
    return _current_identity.get()


def require_current_identity() -> Nip98Identity:
    identity = get_current_identity()
    if identity is None:
        raise RuntimeError("no authenticated identity in this request context")
    return identity
