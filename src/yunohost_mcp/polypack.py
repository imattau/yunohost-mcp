"""Small synchronous façade over the optional local Polypack MCP service.

The YunoHost MCP server's tool handlers are synchronous and are dispatched off
the event loop by ``AsyncToolMCPServer`` in production.  This module therefore
keeps the MCP client session self-contained and runs one short async session
per call.  The Polypack service remains the sole owner of its durable store;
this code only forwards typed tool calls over its loopback endpoint.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostUnavailableError


class PolypackUnavailableError(YunohostUnavailableError):
    """The optional Polypack endpoint is not configured or cannot be reached."""


def _loopback_url(url: str) -> str:
    """Validate the configured endpoint before opening a local connection."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
    except ValueError as exc:
        raise ToolInputError("polypack_url is not a valid URL") from exc

    if parsed.scheme not in {"http", "https"} or hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ToolInputError("polypack_url must use an HTTP(S) loopback endpoint")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ToolInputError("polypack_url must not contain credentials, query parameters, or fragments")
    if not parsed.path:
        raise ToolInputError("polypack_url must include the Polypack MCP path")
    return url


def _result_value(result) -> dict:
    """Convert an MCP call result to the structured JSON returned by Polypack."""
    if getattr(result, "is_error", False):
        texts = [getattr(item, "text", "") for item in getattr(result, "content", [])]
        detail = "; ".join(text for text in texts if text) or "unknown Polypack tool error"
        raise PolypackUnavailableError(detail)

    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured

    texts = [getattr(item, "text", "") for item in getattr(result, "content", [])]
    if len(texts) == 1:
        try:
            value = json.loads(texts[0])
        except (TypeError, ValueError):
            value = None
        if isinstance(value, dict):
            return value
    return {"content": [text for text in texts if text]}


@dataclass(frozen=True)
class PolypackClient:
    settings: Settings

    def call_tool(self, tool: str, arguments: dict) -> dict:
        url = self.settings.polypack_url
        if not url:
            raise PolypackUnavailableError(
                "Polypack integration is not configured; set YUNOHOST_MCP_POLYPACK_URL "
                "to the local /mcp/ endpoint"
            )
        _loopback_url(url)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._call_tool(url, tool, arguments))
        raise PolypackUnavailableError("Polypack calls must run outside the MCP event loop")

    async def _call_tool(self, url: str, tool: str, arguments: dict) -> dict:
        try:
            timeout = httpx2.Timeout(self.settings.polypack_timeout_seconds)
            async with httpx2.AsyncClient(timeout=timeout) as http_client:
                transport = streamable_http_client(url, http_client=http_client)
                async with Client(transport) as client:
                    result = await client.call_tool(tool, arguments)
        except Exception as exc:  # noqa: BLE001 - isolate optional local service failures
            raise PolypackUnavailableError(f"Polypack endpoint unavailable: {exc}") from exc
        return _result_value(result)
