"""ASGI middleware enforcing NIP-98 authentication on every HTTP request.

This is deliberately a raw ASGI middleware (not Starlette's BaseHTTPMiddleware)
so it works regardless of what web framework the wrapped app ("mcp"'s
streamable-http Starlette app) uses internally, and so it can read the exact
raw request body bytes NIP-98 signs over before anything else touches them.

Scope note: this authenticates the *transport* (every HTTP request reaching
the MCP endpoint must carry a validly-signed, fresh, non-replayed NIP-98
event). It does not authorize anything — Phase 3 maps the resulting pubkey
to roles/scopes; until that lands, any validly-signed request is accepted
(identity established, no fine-grained authorization yet).
"""

from __future__ import annotations

import json
import logging

from yunohost_mcp.auth.identity import set_current_identity
from yunohost_mcp.auth.nip98 import Nip98Error, verify_nip98_request
from yunohost_mcp.auth.replay import ReplayCache

logger = logging.getLogger(__name__)


class NostrAuthMiddleware:
    """ASGI middleware: verify NIP-98 auth on http requests; pass through everything else unchanged."""

    def __init__(
        self,
        app,
        *,
        replay_cache: ReplayCache | None = None,
        clock_skew_seconds: int = 60,
        exempt_paths: frozenset[str] = frozenset(),
    ) -> None:
        self.app = app
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
            identity = verify_nip98_request(
                authorization_header=authorization,
                method=method,
                url=url,
                body=body,
                replay_cache=self.replay_cache,
                clock_skew_seconds=self.clock_skew_seconds,
            )
        except Nip98Error as exc:
            logger.info("NIP-98 auth rejected for %s %s: %s", method, url, exc)
            await _send_401(send, str(exc))
            return

        set_current_identity(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            set_current_identity(None)


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


async def _send_401(send, reason: str) -> None:
    body = json.dumps({"error": "unauthorized", "reason": reason}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b'Nostr realm="yunohost-mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
