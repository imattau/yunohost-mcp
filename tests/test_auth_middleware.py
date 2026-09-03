"""Integration test: NostrAuthMiddleware wrapping a trivial ASGI app.

Drives the ASGI interface directly (scope/receive/send) rather than pulling
in an HTTP client library, to keep this test self-contained and fast.
"""

from __future__ import annotations

import json

import pytest

from tests.auth_helpers import make_nip98_authorization_header, new_keypair
from yunohost_mcp.auth.identity import get_current_identity
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.replay import ReplayCache

URL = "http://testserver/mcp"


async def echo_identity_app(scope, receive, send):
    """Downstream app: reads the body, echoes back whether an identity was set."""
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    identity = get_current_identity()
    payload = json.dumps(
        {
            "seen_body": body.decode() if body else None,
            "authenticated": identity is not None,
            "pubkey": identity.pubkey if identity else None,
        }
    ).encode()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": payload})


def _make_scope(*, method: str, path: str, headers: dict[str, str]) -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "root_path": "",
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }


async def _call(app, scope, body: bytes = b"") -> tuple[int, dict]:
    sent = []
    body_delivered = False

    async def receive():
        nonlocal body_delivered
        if not body_delivered:
            body_delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)

    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    response_body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    parsed = json.loads(response_body) if response_body else {}
    return status, parsed


@pytest.mark.anyio
async def test_missing_auth_header_rejected_with_401():
    app = NostrAuthMiddleware(echo_identity_app)
    scope = _make_scope(method="GET", path="/mcp", headers={"host": "testserver"})
    status, _ = await _call(app, scope)
    assert status == 401


@pytest.mark.anyio
async def test_valid_signed_get_request_passes_through():
    sk, pubkey = new_keypair()
    app = NostrAuthMiddleware(echo_identity_app)
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    scope = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status, data = await _call(app, scope)
    assert status == 200
    assert data["authenticated"] is True
    assert data["pubkey"] == pubkey


@pytest.mark.anyio
async def test_valid_signed_post_with_body_passes_body_through_unchanged():
    sk, pubkey = new_keypair()
    app = NostrAuthMiddleware(echo_identity_app)
    body = b'{"hello":"world"}'
    header = make_nip98_authorization_header(sk, pubkey, method="POST", url=URL, body=body)
    scope = _make_scope(method="POST", path="/mcp", headers={"host": "testserver", "authorization": header})
    status, data = await _call(app, scope, body=body)
    assert status == 200
    assert data["seen_body"] == body.decode()
    assert data["authenticated"] is True


@pytest.mark.anyio
async def test_replayed_request_rejected_on_second_call():
    sk, pubkey = new_keypair()
    replay_cache = ReplayCache()
    app = NostrAuthMiddleware(echo_identity_app, replay_cache=replay_cache)
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)

    scope1 = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status1, _ = await _call(app, scope1)
    assert status1 == 200

    scope2 = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status2, _ = await _call(app, scope2)
    assert status2 == 401


@pytest.mark.anyio
async def test_exempt_path_bypasses_auth():
    app = NostrAuthMiddleware(echo_identity_app, exempt_paths=frozenset({"/healthz"}))
    scope = _make_scope(method="GET", path="/healthz", headers={"host": "testserver"})
    status, data = await _call(app, scope)
    assert status == 200
    assert data["authenticated"] is False


@pytest.fixture
def anyio_backend():
    return "asyncio"
