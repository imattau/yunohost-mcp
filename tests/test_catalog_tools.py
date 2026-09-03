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


def test_catalog_relays_falls_back_to_nostr_catalog_ynh_env_file(tmp_path: Path):
    # yunohost-mcp deliberately has no relay setting of its own (it
    # already piggybacks on nostr_catalog_ynh's CLI binary and publisher
    # key) - it should pick up that app's NOSTR_YNH_RELAYS instead of
    # requiring a second, separately-maintained relay list.
    env_path = tmp_path / "nostr-catalogd.env"
    env_path.write_text("NOSTR_YNH_RELAYS=wss://relay.damus.io,wss://nos.lol\nNOSTR_YNH_TRUSTED_PUBLISHERS=\n")
    adapter = YunohostAdapter(Settings(fake_yunohost=False, catalog_relays="", catalog_relays_env_path=env_path))
    assert adapter._catalog_relays() == ["wss://relay.damus.io", "wss://nos.lol"]


def test_catalog_relays_explicit_override_wins_over_nostr_catalog_ynh_env_file(tmp_path: Path):
    env_path = tmp_path / "nostr-catalogd.env"
    env_path.write_text("NOSTR_YNH_RELAYS=wss://relay.damus.io\n")
    adapter = YunohostAdapter(
        Settings(fake_yunohost=False, catalog_relays="wss://relay.override", catalog_relays_env_path=env_path)
    )
    assert adapter._catalog_relays() == ["wss://relay.override"]


def test_catalog_relays_is_empty_when_env_file_is_missing(tmp_path: Path):
    adapter = YunohostAdapter(
        Settings(fake_yunohost=False, catalog_relays="", catalog_relays_env_path=tmp_path / "does-not-exist.env")
    )
    assert adapter._catalog_relays() == []


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
