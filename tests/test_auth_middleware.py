"""Integration test: NostrAuthMiddleware (NIP-98 authn + identity.toml authz)
wrapping a trivial ASGI app.

Drives the ASGI interface directly (scope/receive/send) rather than pulling
in an HTTP client library, to keep this test self-contained and fast.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from tests.auth_helpers import make_delegation_header, make_nip98_authorization_header, new_keypair
from yunohost_mcp.auth.identity import IdentityRecord, IdentityStore, get_current_request
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.auth.server_identity import ServerIdentity
from yunohost_mcp.policy.roles import scopes_for_roles

URL = "http://testserver/mcp"


def _store_with(pubkey: str, *, roles: tuple[str, ...] = ("readonly",), expires=None) -> IdentityStore:
    record = IdentityRecord(
        pubkey=pubkey, name="test-agent", roles=roles, scopes=scopes_for_roles(roles), expires=expires
    )
    return IdentityStore({pubkey: record})


async def echo_identity_app(scope, receive, send):
    """Downstream app: reads the body, echoes back the resolved identity."""
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    request = get_current_request()
    payload = json.dumps(
        {
            "seen_body": body.decode() if body else None,
            "authenticated": request is not None,
            "pubkey": request.pubkey if request else None,
            "scopes": sorted(s.value for s in request.scopes) if request else [],
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
    body_delivered = False

    async def receive():
        nonlocal body_delivered
        if not body_delivered:
            body_delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    sent = []

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)

    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    response_body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    parsed = json.loads(response_body) if response_body else {}
    return status, parsed


@pytest.mark.anyio
async def test_missing_auth_header_rejected_with_401():
    app = NostrAuthMiddleware(echo_identity_app, identity_store=IdentityStore({}))
    scope = _make_scope(method="GET", path="/mcp", headers={"host": "testserver"})
    status, _ = await _call(app, scope)
    assert status == 401


@pytest.mark.anyio
async def test_valid_signature_but_unmapped_pubkey_rejected_with_403():
    sk, pubkey = new_keypair()
    app = NostrAuthMiddleware(echo_identity_app, identity_store=IdentityStore({}))
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    scope = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status, _ = await _call(app, scope)
    assert status == 403


@pytest.mark.anyio
async def test_expired_identity_rejected_with_403():
    sk, pubkey = new_keypair()
    expired = datetime.now(timezone.utc) - timedelta(days=1)
    store = _store_with(pubkey, expires=expired)
    app = NostrAuthMiddleware(echo_identity_app, identity_store=store)
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    scope = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status, _ = await _call(app, scope)
    assert status == 403


@pytest.mark.anyio
async def test_valid_signed_get_request_from_known_identity_passes_through():
    sk, pubkey = new_keypair()
    store = _store_with(pubkey)
    app = NostrAuthMiddleware(echo_identity_app, identity_store=store)
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    scope = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status, data = await _call(app, scope)
    assert status == 200
    assert data["authenticated"] is True
    assert data["pubkey"] == pubkey
    assert "server.read" in data["scopes"]


@pytest.mark.anyio
async def test_valid_signed_post_with_body_passes_body_through_unchanged():
    sk, pubkey = new_keypair()
    store = _store_with(pubkey)
    app = NostrAuthMiddleware(echo_identity_app, identity_store=store)
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
    store = _store_with(pubkey)
    replay_cache = ReplayCache()
    app = NostrAuthMiddleware(echo_identity_app, identity_store=store, replay_cache=replay_cache)
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)

    scope1 = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status1, _ = await _call(app, scope1)
    assert status1 == 200

    scope2 = _make_scope(method="GET", path="/mcp", headers={"host": "testserver", "authorization": header})
    status2, _ = await _call(app, scope2)
    assert status2 == 401


@pytest.mark.anyio
async def test_exempt_path_bypasses_auth():
    app = NostrAuthMiddleware(echo_identity_app, identity_store=IdentityStore({}), exempt_paths=frozenset({"/healthz"}))
    scope = _make_scope(method="GET", path="/healthz", headers={"host": "testserver"})
    status, data = await _call(app, scope)
    assert status == 200
    assert data["authenticated"] is False


@pytest.mark.anyio
async def test_request_body_limit_rejects_oversized_body():
    app = NostrAuthMiddleware(
        echo_identity_app,
        identity_store=IdentityStore({}),
        max_request_body_bytes=3,
    )
    scope = _make_scope(method="POST", path="/mcp", headers={})
    status, payload = await _call(app, scope, body=b"1234")
    assert status == 413
    assert payload["error"] == "forbidden"


@pytest.mark.anyio
async def test_delegated_agent_authenticates_via_x_nostr_delegation_header(tmp_path):
    server_identity = ServerIdentity.load_or_generate(tmp_path / "server.key")
    owner_sk, owner_pubkey = new_keypair()
    agent_sk, agent_pubkey = new_keypair()

    owner_store = _store_with(owner_pubkey, roles=("readonly",))
    app = NostrAuthMiddleware(
        echo_identity_app,
        identity_store=owner_store,
        server_identity=server_identity,
        revocation_store=RevocationStore(frozenset()),
    )

    import time

    delegation_header = make_delegation_header(
        owner_sk,
        owner_pubkey,
        delegate_pubkey=agent_pubkey,
        server_pubkey=server_identity.pubkey_hex,
        scopes=["apps.read"],
        expires_at=int(time.time()) + 3600,
    )
    # The agent signs the HTTP request itself with its OWN key - the
    # delegation header is separate from (and doesn't replace) NIP-98.
    nip98_header = make_nip98_authorization_header(agent_sk, agent_pubkey, method="GET", url=URL)
    scope = _make_scope(
        method="GET",
        path="/mcp",
        headers={"host": "testserver", "authorization": nip98_header, "x-nostr-delegation": delegation_header},
    )
    status, data = await _call(app, scope)
    assert status == 200
    assert data["authenticated"] is True
    assert data["pubkey"] == agent_pubkey  # the AGENT's pubkey, not the owner's
    assert "apps.read" in data["scopes"]


@pytest.mark.anyio
async def test_delegation_ignored_when_server_identity_not_configured(tmp_path):
    owner_sk, owner_pubkey = new_keypair()
    agent_sk, agent_pubkey = new_keypair()
    owner_store = _store_with(owner_pubkey, roles=("readonly",))
    # No server_identity passed - delegation support is off entirely.
    app = NostrAuthMiddleware(echo_identity_app, identity_store=owner_store)

    import time

    delegation_header = make_delegation_header(
        owner_sk,
        owner_pubkey,
        delegate_pubkey=agent_pubkey,
        server_pubkey="s" * 64,
        scopes=["apps.read"],
        expires_at=int(time.time()) + 3600,
    )
    nip98_header = make_nip98_authorization_header(agent_sk, agent_pubkey, method="GET", url=URL)
    scope = _make_scope(
        method="GET",
        path="/mcp",
        headers={"host": "testserver", "authorization": nip98_header, "x-nostr-delegation": delegation_header},
    )
    status, _ = await _call(app, scope)
    assert status == 403


@pytest.mark.anyio
async def test_revoked_delegation_rejected_by_middleware(tmp_path):
    server_identity = ServerIdentity.load_or_generate(tmp_path / "server.key")
    owner_sk, owner_pubkey = new_keypair()
    agent_sk, agent_pubkey = new_keypair()
    owner_store = _store_with(owner_pubkey, roles=("readonly",))

    import time

    from tests.auth_helpers import make_delegation_event

    event = make_delegation_event(
        owner_sk,
        owner_pubkey,
        delegate_pubkey=agent_pubkey,
        server_pubkey=server_identity.pubkey_hex,
        scopes=["apps.read"],
        expires_at=int(time.time()) + 3600,
    )
    app = NostrAuthMiddleware(
        echo_identity_app,
        identity_store=owner_store,
        server_identity=server_identity,
        revocation_store=RevocationStore(frozenset({event.id})),
    )

    import base64
    import json as _json

    delegation_header = base64.b64encode(_json.dumps(event.model_dump()).encode()).decode()
    nip98_header = make_nip98_authorization_header(agent_sk, agent_pubkey, method="GET", url=URL)
    scope = _make_scope(
        method="GET",
        path="/mcp",
        headers={"host": "testserver", "authorization": nip98_header, "x-nostr-delegation": delegation_header},
    )
    status, _ = await _call(app, scope)
    assert status == 403


@pytest.fixture
def anyio_backend():
    return "asyncio"
