from __future__ import annotations

import json
import base64
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from yunohost_mcp.broker.operations import OPERATIONS
from yunohost_mcp.broker.helper import authorize_request
from yunohost_mcp.broker.protocol import (
    BrokerProtocolError,
    BrokerRequest,
    MAX_MESSAGE_BYTES,
    decode_request,
    encode_response,
    decode_original_body,
)
from yunohost_mcp.auth.identity import IdentityRecord, IdentityStore
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.server_identity import ServerIdentity
from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.policy.roles import scopes_for_roles
from coincurve import PrivateKey, PublicKeyXOnly
import hashlib
import time


def test_request_round_trips_with_original_auth_context():
    request = BrokerRequest(
        request_id="request-1",
        operation="app.info",
        arguments={"app": "nextcloud", "full": True},
        authorization="Nostr signed-event",
        method="POST",
        url="https://example.test/mcp",
        body_sha256="a" * 64,
        body_b64=base64.b64encode(b"payload").decode(),
        delegation="delegation-event",
    )

    decoded = decode_request(request.encode().rstrip(b"\n"))

    assert decoded == request


def test_unknown_auth_fields_are_rejected():
    value = {
        "protocol": 1,
        "request_id": "request-1",
        "operation": "app.info",
        "arguments": {},
        "auth": {"authorization": "x", "private_key": "nsec1secret"},
    }

    with pytest.raises(BrokerProtocolError, match="unknown auth field"):
        decode_request(json.dumps(value).encode())


def test_unknown_top_level_fields_are_rejected():
    value = {
        "protocol": 1,
        "request_id": "request-1",
        "operation": "app.info",
        "arguments": {},
        "unexpected": "data",
    }
    with pytest.raises(BrokerProtocolError, match="unknown broker request field"):
        decode_request(json.dumps(value).encode())


def test_oversized_messages_are_rejected():
    with pytest.raises(BrokerProtocolError, match="exceeds message limit"):
        decode_request(b"x" * (MAX_MESSAGE_BYTES + 1))


def test_response_is_versioned_and_correlated():
    response = json.loads(encode_response(request_id="request-1", ok=True, result={"ok": True}))

    assert response == {"protocol": 1, "request_id": "request-1", "ok": True, "result": {"ok": True}}


def test_response_serializes_native_yunohost_values():
    response = json.loads(
        encode_response(
            request_id="request-1",
            ok=True,
            result={"updated": datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc)},
        )
    )

    assert response["result"]["updated"] == "2026-09-05T10:00:00+00:00"


def test_original_body_hash_is_checked():
    request = BrokerRequest(
        request_id="request-1",
        operation="app.info",
        arguments={},
        body_sha256="0" * 64,
        body_b64=base64.b64encode(b"payload").decode(),
    )
    with pytest.raises(BrokerProtocolError, match="does not match"):
        decode_original_body(request)


def test_registry_contains_only_explicit_operations():
    assert "app.info" in OPERATIONS
    assert OPERATIONS["app.upgrade"].required_scope == "apps.upgrade"
    assert OPERATIONS["app.remove"].required_scope == "apps.remove"
    assert OPERATIONS["app.change_url"].required_scope == "apps.upgrade"
    assert OPERATIONS["app.config_set"].required_scope == "apps.config.write"
    assert OPERATIONS["backup.restore"].required_scope == "backups.restore"
    assert OPERATIONS["system.upgrade"].required_scope == "system.upgrade"
    assert OPERATIONS["migrations.run"].required_scope == "system.migrate"
    assert OPERATIONS["user.create"].required_scope == "users.write"
    assert OPERATIONS["user.update"].required_scope == "users.write"
    assert OPERATIONS["user.delete"].required_scope == "users.delete"
    assert OPERATIONS["user.group_create"].required_scope == "users.write"
    assert OPERATIONS["user.group_update"].required_scope == "users.write"
    assert OPERATIONS["user.group_delete"].required_scope == "users.delete"
    assert OPERATIONS["user.permission_add"].required_scope == "users.write"
    assert OPERATIONS["user.permission_remove"].required_scope == "users.write"
    assert OPERATIONS["domain.add"].required_scope == "domains.write"
    assert OPERATIONS["domain.cert_install"].required_scope == "domains.write"
    assert OPERATIONS["updates.refresh"].required_scope == "system.update"
    assert OPERATIONS["diagnosis.run"].required_scope == "diagnosis.read"
    assert OPERATIONS["catalog.package_inspect"].required_scope == "catalog.inspect"
    assert OPERATIONS["catalog.verify"].required_scope == "catalog.verify"
    assert OPERATIONS["catalog.list"].required_scope == "catalog.inspect"
    assert OPERATIONS["catalog.publish_plan"].required_scope == "catalog.inspect"
    assert OPERATIONS["catalog.publish"].required_scope == "catalog.publish"
    assert OPERATIONS["package.inspect"].required_scope == "packages.inspect"
    assert OPERATIONS["package.lint"].required_scope == "packages.inspect"
    assert OPERATIONS["package.run_tests"].required_scope == "packages.test"
    assert OPERATIONS["package.install_test"].required_scope == "packages.test"
    assert OPERATIONS["package.upgrade_test"].required_scope == "packages.test"
    assert OPERATIONS["package.backup_test"].required_scope == "packages.test"
    assert OPERATIONS["package.restore_test"].required_scope == "packages.test"
    assert OPERATIONS["package.change_url_test"].required_scope == "packages.test"
    assert OPERATIONS["package.remove_test"].required_scope == "packages.test"
    assert OPERATIONS["safe.upgrade"].required_scope == "apps.upgrade"
    assert OPERATIONS["repair.app"].required_scope == "services.restart"
    assert OPERATIONS["diagnose.app"].required_scope == "apps.read"
    assert OPERATIONS["validate.server"].required_scope == "server.read"
    assert OPERATIONS["app.install"].required_scope == "apps.install"
    assert OPERATIONS["backup.create"].required_scope == "backups.create"
    assert OPERATIONS["service.restart"].required_scope == "services.restart"
    assert all("shell" not in name and "exec" not in name for name in OPERATIONS)


def test_helper_revalidates_a_real_nip98_signature(tmp_path):
    client_key = PrivateKey()
    client_pubkey = PublicKeyXOnly.from_valid_secret(client_key.secret).format().hex()
    body = b'{"jsonrpc":"2.0","method":"tools/call"}'
    url = "https://example.test/mcp"
    event = sign_event(
        client_key,
        pubkey=client_pubkey,
        kind=27235,
        tags=[["u", url], ["method", "POST"], ["payload", hashlib.sha256(body).hexdigest()]],
        created_at=int(time.time()),
    )
    authorization = "Nostr " + base64.b64encode(json.dumps(event.model_dump()).encode()).decode()
    server_key = PrivateKey()
    server_pubkey = PublicKeyXOnly.from_valid_secret(server_key.secret).format().hex()
    server_identity = ServerIdentity(server_key, server_pubkey)
    record = IdentityRecord(
        pubkey=client_pubkey,
        name="test-agent",
        roles=("readonly",),
        scopes=scopes_for_roles(("readonly",)),
    )
    request = BrokerRequest(
        request_id="request-1",
        operation="app.info",
        arguments={"app": "nextcloud"},
        authorization=authorization,
        method="POST",
        url=url,
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_b64=base64.b64encode(body).decode(),
    )
    server = SimpleNamespace(
        identity_store=IdentityStore({client_pubkey: record}),
        replay_cache=ReplayCache(),
        server_identity=server_identity,
        revocation_store=SimpleNamespace(is_revoked=lambda _event_id: False),
    )

    authenticated = authorize_request(request, server)

    assert authenticated.pubkey == client_pubkey
    assert authenticated.has_scope(next(iter(record.scopes)))
