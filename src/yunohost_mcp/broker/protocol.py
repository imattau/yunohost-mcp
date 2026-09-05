"""Small, versioned protocol used by the unprivileged MCP frontend.

The protocol is intentionally line-delimited JSON.  It is used only over a
local Unix stream socket; it is not an HTTP or public API.  Keeping the wire
format explicit makes the root helper auditable and lets us reject unknown
fields and oversized messages before dispatching anything privileged.
"""

from __future__ import annotations

import json
import secrets
import base64
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1_048_576


class BrokerProtocolError(ValueError):
    """A broker message is malformed or exceeds the protocol limits."""


@dataclass(frozen=True)
class BrokerRequest:
    request_id: str
    operation: str
    arguments: dict[str, Any]
    # These fields describe the *original* external MCP request.  They must
    # not be replaced with the internal socket request's method/body.
    authorization: str | None = None
    method: str | None = None
    url: str | None = None
    body_sha256: str | None = None
    body_b64: str | None = None
    delegation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": PROTOCOL_VERSION,
            "request_id": self.request_id,
            "operation": self.operation,
            "arguments": self.arguments,
            "auth": {
                "authorization": self.authorization,
                "method": self.method,
                "url": self.url,
                "body_sha256": self.body_sha256,
                "body_b64": self.body_b64,
                "delegation": self.delegation,
            },
        }

    def encode(self) -> bytes:
        raw = json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False).encode()
        if len(raw) > MAX_MESSAGE_BYTES:
            raise BrokerProtocolError("broker request exceeds message limit")
        return raw + b"\n"

    @classmethod
    def from_dict(cls, value: object) -> "BrokerRequest":
        if not isinstance(value, dict) or value.get("protocol") != PROTOCOL_VERSION:
            raise BrokerProtocolError("unsupported or missing broker protocol version")
        allowed = {"protocol", "request_id", "operation", "arguments", "auth"}
        if set(value) - allowed:
            raise BrokerProtocolError("unknown broker request field")
        request_id = value.get("request_id")
        operation = value.get("operation")
        arguments = value.get("arguments", {})
        auth = value.get("auth") or {}
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise BrokerProtocolError("invalid request_id")
        if not isinstance(operation, str) or not operation or len(operation) > 128:
            raise BrokerProtocolError("invalid operation")
        if not isinstance(arguments, dict):
            raise BrokerProtocolError("arguments must be an object")
        if not isinstance(auth, dict):
            raise BrokerProtocolError("auth must be an object")
        allowed_auth = {"authorization", "method", "url", "body_sha256", "body_b64", "delegation"}
        if set(auth) - allowed_auth:
            raise BrokerProtocolError("unknown auth field")
        return cls(
            request_id=request_id,
            operation=operation,
            arguments=arguments,
            authorization=_optional_string(auth, "authorization"),
            method=_optional_string(auth, "method"),
            url=_optional_string(auth, "url"),
            body_sha256=_optional_string(auth, "body_sha256"),
            body_b64=_optional_string(auth, "body_b64"),
            delegation=_optional_string(auth, "delegation"),
        )


def new_request_id() -> str:
    return secrets.token_urlsafe(18)


def decode_request(line: bytes) -> BrokerRequest:
    if len(line) > MAX_MESSAGE_BYTES:
        raise BrokerProtocolError("broker request exceeds message limit")
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerProtocolError("invalid broker JSON") from exc
    return BrokerRequest.from_dict(value)


def decode_original_body(request: BrokerRequest) -> bytes:
    """Decode the exact body NIP-98 signed, rejecting hash mismatches."""
    if request.body_b64 is None:
        body = b""
    else:
        try:
            body = base64.b64decode(request.body_b64, validate=True)
        except (ValueError, UnicodeError) as exc:
            raise BrokerProtocolError("auth.body_b64 is not valid base64") from exc
    if request.body_sha256 is not None:
        import hashlib

        if hashlib.sha256(body).hexdigest() != request.body_sha256:
            raise BrokerProtocolError("auth.body_sha256 does not match auth.body_b64")
    return body


def encode_response(*, request_id: str, ok: bool, result: Any = None, error: str | None = None) -> bytes:
    value: dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": ok,
    }
    if ok:
        value["result"] = result
    else:
        value["error"] = error or "broker operation failed"
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX_MESSAGE_BYTES:
        raise BrokerProtocolError("broker response exceeds message limit")
    return raw + b"\n"


def _optional_string(value: dict[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is not None and not isinstance(item, str):
        raise BrokerProtocolError(f"auth.{key} must be a string")
    return item
