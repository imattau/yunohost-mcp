from __future__ import annotations

from pathlib import Path

import pytest
from mcp.client import Client

from yunohost_mcp.config import Settings
from yunohost_mcp.auth.identity import LOCAL_STDIO_REQUEST, set_current_request
from yunohost_mcp.server import mcp
from yunohost_mcp.yunohost.adapter import YunohostAdapter


def test_catalog_plan_fake_mode_requires_a_local_source(tmp_path: Path):
    adapter = YunohostAdapter(
        Settings(fake_yunohost=True, catalog_relays="wss://relay.test")
    )
    result = adapter.catalog_publish_plan(str(tmp_path))
    assert result["app_id"] == "example"
    assert result["relays"] == ["wss://relay.test"]
    assert result["naddr"].startswith("naddr")


def test_catalog_remote_source_requires_explicit_ref():
    adapter = YunohostAdapter(Settings(fake_yunohost=False))
    try:
        adapter.catalog_publish_plan("https://github.com/example/app_ynh")
    except ValueError as exc:
        assert "explicit ref" in str(exc)
    else:
        raise AssertionError("remote source without ref was accepted")


def test_catalog_verify_fake_mode_never_needs_publisher_key():
    adapter = YunohostAdapter(Settings(fake_yunohost=True))
    result = adapter.catalog_verify("naddr1qqxyz")
    assert result["valid"] is True


@pytest.mark.anyio
async def test_catalog_publish_requires_confirmation_then_executes(tmp_path: Path):
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            planned = await client.call_tool("catalog_publish_plan", {"source": str(tmp_path)})
            assert planned.is_error is not True
            plan_id = planned.structured_content["plan_id"]

            pending = await client.call_tool("catalog_publish", {"plan_id": plan_id})
            assert pending.is_error is not True
            assert pending.structured_content["confirmation_required"] is True

            published = await client.call_tool(
                "catalog_publish",
                {
                    "plan_id": plan_id,
                    "confirmation_id": pending.structured_content["confirmation_id"],
                },
            )
            assert published.is_error is not True
            assert published.structured_content["published"] is True
    finally:
        set_current_request(None)
