"""Unprivileged frontend client for the local YunoHost broker."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
from pathlib import Path
from typing import Any

from yunohost_mcp.auth.identity import require_current_request
from yunohost_mcp.broker.protocol import BrokerProtocolError, BrokerRequest, new_request_id
from yunohost_mcp.yunohost.adapter import YunohostUnavailableError


class BrokerClientError(YunohostUnavailableError):
    """The local broker could not execute or validate a request."""


def call(operation: str, arguments: dict[str, Any], *, socket_path: Path, timeout: float = 120) -> dict[str, Any]:
    """Forward one operation with the exact current HTTP auth envelope."""
    current = require_current_request()
    if not current.authorization or not current.method or not current.url:
        raise BrokerClientError("broker calls require an authenticated HTTP request")
    body = current.body
    request = BrokerRequest(
        request_id=new_request_id(),
        operation=operation,
        arguments=arguments,
        authorization=current.authorization,
        method=current.method,
        url=current.url,
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_b64=base64.b64encode(body).decode(),
        delegation=current.delegation,
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
            sock.sendall(request.encode())
            raw = _read_line(sock)
    except OSError as exc:
        raise BrokerClientError(f"could not reach YunoHost broker: {exc}") from exc
    try:
        response = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerClientError("broker returned invalid JSON") from exc
    if response.get("protocol") != 1 or response.get("request_id") != request.request_id:
        raise BrokerClientError("broker response protocol or request_id mismatch")
    if not response.get("ok"):
        raise BrokerClientError(str(response.get("error", "broker operation failed")))
    result = response.get("result")
    if not isinstance(result, dict):
        raise BrokerClientError("broker result must be an object")
    return result


def _read_line(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > 1_048_576:
            raise BrokerProtocolError("broker response exceeds message limit")
    return data.rstrip(b"\n")
