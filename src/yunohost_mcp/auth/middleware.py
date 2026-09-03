"""ASGI middleware enforcing NIP-98 authentication AND identity.toml
authorization on every HTTP request, before it reaches the MCP session.

This is deliberately a raw ASGI middleware (not Starlette's BaseHTTPMiddleware)
so it works regardless of what web framework the wrapped app ("mcp"'s
streamable-http Starlette app) uses internally, and so it can read the exact
raw request body bytes NIP-98 signs over before anything else touches them.

Two independent stages, per PLAN.md's architecture:
  1. Authentication (NIP-98): proves a request was signed, fresh, and not
     replayed, by the holder of `pubkey`'s private key. Failure -> 401.
  2. Authorization (identity.toml): resolves `pubkey` to an IdentityRecord
     with roles/scopes. No record, an expired record, or an unknown role ->
     zero scopes -> the request is rejected here too, with 403 (identity
     proven, but not authorized for anything). A signature alone never
     grants access.

Individual tool handlers still check the specific scope they need via
auth/identity.py's AuthenticatedRequest.has_scope() — this middleware only
guarantees that whatever reaches a tool handler has *some* non-expired,
role-mapped identity attached.
"""

from __future__ import annotations

import json
import logging

from yunohost_mcp.auth.identity import AuthenticatedRequest, IdentityStore, set_current_request
from yunohost_mcp.auth.nip98 import Nip98Error, verify_nip98_request
from yunohost_mcp.auth.replay import ReplayCache

logger = logging.getLogger(__name__)


class NostrAuthMiddleware:
    """ASGI middleware: NIP-98 authentication + identity.toml authorization on http requests."""

    def __init__(
        self,
        app,
        *,
        identity_store: IdentityStore,
        replay_cache: ReplayCache | None = None,
        clock_skew_seconds: int = 60,
        exempt_paths: frozenset[str] = frozenset(),
    ) -> None:
        self.app = app
        self.identity_store = identity_store
        self.replay_cache = replay_cache or ReplayCache()
        self.clock_skew_seconds = clock_skew_seconds
        self.exempt_paths = exempt_paths

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["path"] in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        body, receive = await _buffer_body(receive)

        method = scope["method"]
        url = _reconstruct_url(scope)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        authorization = headers.get("authorization")

        try:
            nip98_identity = verify_nip98_request(
                authorization_header=authorization,
                method=method,
                url=url,
                body=body,
                replay_cache=self.replay_cache,
                clock_skew_seconds=self.clock_skew_seconds,
            )
        except Nip98Error as exc:
            logger.info("NIP-98 auth rejected for %s %s: %s", method, url, exc)
            await _send_error(send, 401, str(exc), www_authenticate=True)
            return

        record = self.identity_store.lookup(nip98_identity.pubkey)
        if record is None:
            logger.info("Unknown pubkey %s rejected for %s %s", nip98_identity.pubkey, method, url)
            await _send_error(send, 403, "pubkey is not in identity.toml: no roles granted")
            return
        if record.is_expired():
            logger.info("Expired identity %s (%s) rejected for %s %s", record.name, nip98_identity.pubkey, method, url)
            await _send_error(send, 403, f"identity {record.name!r} expired at {record.expires}")
            return

        request = AuthenticatedRequest(
            pubkey=nip98_identity.pubkey,
            event_id=nip98_identity.event_id,
            event_created_at=nip98_identity.created_at,
            identity=record,
        )
        set_current_request(request)
        try:
            await self.app(scope, receive, send)
        finally:
            set_current_request(None)


async def _buffer_body(receive):
    """Fully drain `receive`, returning (body_bytes, replacement_receive).

    NIP-98 needs the exact body bytes to check the 'payload' tag before the
    downstream app sees anything, but ASGI bodies are normally consumed
    once. Buffer it and hand back a receive callable that replays it.
    """
    chunks = []
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        more_body = message.get("more_body", False)
    body = b"".join(chunks)

    sent = False

    async def replay_receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return body, replay_receive


def _reconstruct_url(scope) -> str:
    scheme = scope.get("scheme", "http")
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    host = headers.get("host")
    if not host:
        server_host, server_port = scope.get("server", ("localhost", None))
        host = server_host if server_port is None else f"{server_host}:{server_port}"
    path = scope.get("root_path", "") + scope["path"]
    query = scope.get("query_string", b"").decode("latin-1")
    url = f"{scheme}://{host}{path}"
    if query:
        url += f"?{query}"
    return url


async def _send_error(send, status: int, reason: str, *, www_authenticate: bool = False) -> None:
    body = json.dumps({"error": "unauthorized" if status == 401 else "forbidden", "reason": reason}).encode()
    headers = [(b"content-type", b"application/json")]
    if www_authenticate:
        headers.append((b"www-authenticate", b'Nostr realm="yunohost-mcp"'))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
