"""ASGI middleware enforcing NIP-98 authentication AND identity.toml
authorization on every HTTP request, before it reaches the MCP session.

This is deliberately a raw ASGI middleware (not Starlette's BaseHTTPMiddleware)
so it works regardless of what web framework the wrapped app ("mcp"'s
streamable-http Starlette app) uses internally, and so it can read the exact
raw request body bytes NIP-98 signs over before anything else touches them.

Three independent stages, per PLAN.md's architecture:
  1. Authentication (NIP-98): proves a request was signed, fresh, and not
     replayed, by the holder of `pubkey`'s private key. Failure -> 401.
  2. Authorization (identity.toml): resolves `pubkey` to an IdentityRecord
     with roles/scopes.
  3. Delegation (Phase 11, optional): if `pubkey` has no direct
     identity.toml entry (or an expired one), and the request carries an
     `X-Nostr-Delegation` header, that header is checked as a delegation
     event naming `pubkey` as its delegate - see auth/delegation.py. Only
     attempted when `server_identity` is configured; delegation is off
     entirely otherwise (`X-Nostr-Delegation` is then just ignored).
  No record, an expired one, an unknown role, or an invalid/absent
  delegation -> zero scopes -> 403 (identity proven, but not authorized for
  anything). A signature alone never grants access.

Individual tool handlers still check the specific scope they need via
auth/identity.py's AuthenticatedRequest.has_scope() — this middleware only
guarantees that whatever reaches a tool handler has *some* non-expired,
scope-bearing identity attached.
"""

from __future__ import annotations

import base64
import json
import logging

import anyio

from yunohost_mcp.auth.delegation import DelegationError, resolve_delegated_identity, verify_delegation_event
from yunohost_mcp.auth.identity import AuthenticatedRequest, IdentityRecord, IdentityStore, set_current_request
from yunohost_mcp.auth.nip98 import Nip98Error, verify_nip98_request
from yunohost_mcp.auth.nostr import NostrEvent, NostrEventError
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.auth.server_identity import ServerIdentity

logger = logging.getLogger(__name__)


class NostrAuthMiddleware:
    """ASGI middleware: NIP-98 authentication + identity.toml/delegation authorization on http requests."""

    def __init__(
        self,
        app,
        *,
        identity_store: IdentityStore,
        replay_cache: ReplayCache | None = None,
        clock_skew_seconds: int = 60,
        exempt_paths: frozenset[str] = frozenset(),
        server_identity: ServerIdentity | None = None,
        revocation_store: RevocationStore | None = None,
        max_request_body_bytes: int = 1_048_576,
        request_timeout_seconds: int = 120,
        max_concurrent_requests: int = 8,
    ) -> None:
        self.app = app
        self.identity_store = identity_store
        self.replay_cache = replay_cache or ReplayCache()
        self.clock_skew_seconds = clock_skew_seconds
        self.exempt_paths = exempt_paths
        self.server_identity = server_identity
        self.revocation_store = revocation_store or RevocationStore(frozenset())
        self.max_request_body_bytes = max_request_body_bytes
        self.request_timeout_seconds = request_timeout_seconds
        self._request_slots = anyio.Semaphore(max_concurrent_requests)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["path"] in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        try:
            body, receive = await _buffer_body(receive, max_bytes=self.max_request_body_bytes)
        except RequestTooLargeError as exc:
            await _send_error(send, 413, str(exc))
            return

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

        record = self._resolve_identity(nip98_identity.pubkey, headers)
        if record is None:
            logger.info("Unknown/unauthorized pubkey %s rejected for %s %s", nip98_identity.pubkey, method, url)
            await _send_error(send, 403, "pubkey is not in identity.toml, and no valid delegation was presented")
            return

        request = AuthenticatedRequest(
            pubkey=nip98_identity.pubkey,
            event_id=nip98_identity.event_id,
            event_created_at=nip98_identity.created_at,
            identity=record,
        )
        set_current_request(request)
        try:
            with anyio.fail_after(self.request_timeout_seconds):
                async with self._request_slots:
                    await self.app(scope, receive, send)
        finally:
            set_current_request(None)

    def _resolve_identity(self, pubkey: str, headers: dict[str, str]) -> IdentityRecord | None:
        record = self.identity_store.lookup(pubkey)
        if record is not None and not record.is_expired():
            return record

        delegation_header = headers.get("x-nostr-delegation")
        if self.server_identity is None or not delegation_header:
            return None

        try:
            raw = json.loads(base64.b64decode(delegation_header, validate=True))
            event = NostrEvent.model_validate(raw)
            claim = verify_delegation_event(
                event,
                expected_delegate_pubkey=pubkey,
                server_pubkey_hex=self.server_identity.pubkey_hex,
                revocation_store=self.revocation_store,
            )
            return resolve_delegated_identity(claim, identity_store=self.identity_store)
        except (ValueError, NostrEventError, DelegationError) as exc:
            logger.info("Delegation rejected for pubkey %s: %s", pubkey, exc)
            return None


class RequestTooLargeError(ValueError):
    """The request body exceeds the configured HTTP limit."""


async def _buffer_body(receive, *, max_bytes: int):
    """Fully drain `receive`, returning (body_bytes, replacement_receive).

    NIP-98 needs the exact body bytes to check the 'payload' tag before the
    downstream app sees anything, but ASGI bodies are normally consumed
    once. Buffer it and hand back a receive callable that replays it.
    """
    chunks = []
    total_bytes = 0
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise RequestTooLargeError(f"request body exceeds {max_bytes} bytes")
        chunks.append(chunk)
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
