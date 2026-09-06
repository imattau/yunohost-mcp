from __future__ import annotations

from pathlib import Path

import pytest
from mcp.client import Client

from yunohost_mcp.config import Settings
from yunohost_mcp.auth.identity import AuthenticatedRequest, LOCAL_STDIO_REQUEST, set_current_request
from yunohost_mcp.server import mcp
import yunohost_mcp.yunohost.adapter as adapter_module
from yunohost_mcp.yunohost.adapter import YunohostAdapter

CALLER_PUBKEY = "b" * 64
CALLER_REQUEST = AuthenticatedRequest(pubkey=CALLER_PUBKEY, event_id="e" * 64, event_created_at=0)


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


def test_catalog_relays_fall_back_to_yunohost_app_setting(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(
        adapter_module,
        "_call_via_system_python",
        lambda module, attr, kwargs, settings: "wss://relay.damus.io,wss://nos.lol"
        if kwargs["key"] == "relays"
        else "",
    )
    adapter = YunohostAdapter(
        Settings(fake_yunohost=False, catalog_relays="", catalog_relays_env_path=tmp_path / "missing.env")
    )
    assert adapter._catalog_relays() == ["wss://relay.damus.io", "wss://nos.lol"]


def test_catalog_relays_disabled_caller_widening_by_default(monkeypatch: pytest.MonkeyPatch):
    # nostr_auth_relay_lookup_socket is None by default - the widening
    # fallback must not even look at the current request, let alone touch
    # a socket, unless a deployment opts in.
    import yunohost_mcp.auth.nostr_auth_relay_lookup as relay_lookup_module

    def _must_not_be_called(pubkey, *, settings):
        raise AssertionError("lookup_linked_relays must not be called when disabled")

    monkeypatch.setattr(relay_lookup_module, "lookup_linked_relays", _must_not_be_called)
    set_current_request(CALLER_REQUEST)
    try:
        adapter = YunohostAdapter(Settings(fake_yunohost=False, catalog_relays="wss://relay.test"))
        assert adapter._catalog_relays() == ["wss://relay.test"]
    finally:
        set_current_request(None)


def test_catalog_relays_widened_with_the_calling_identitys_own_relays(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import yunohost_mcp.auth.nostr_auth_relay_lookup as relay_lookup_module

    monkeypatch.setattr(
        relay_lookup_module,
        "lookup_linked_relays",
        lambda pubkey, *, settings: ["wss://mine.example"] if pubkey == CALLER_PUBKEY else [],
    )
    set_current_request(CALLER_REQUEST)
    try:
        adapter = YunohostAdapter(
            Settings(
                fake_yunohost=False,
                catalog_relays="wss://relay.test",
                nostr_auth_relay_lookup_socket=tmp_path / "relays.sock",
            )
        )
        assert adapter._catalog_relays() == ["wss://relay.test", "wss://mine.example"]
    finally:
        set_current_request(None)


def test_catalog_relays_widening_deduplicates_and_ignores_local_stdio(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import yunohost_mcp.auth.nostr_auth_relay_lookup as relay_lookup_module

    monkeypatch.setattr(
        relay_lookup_module,
        "lookup_linked_relays",
        lambda pubkey, *, settings: ["wss://relay.test"],  # already in the base list
    )
    adapter = YunohostAdapter(
        Settings(
            fake_yunohost=False,
            catalog_relays="wss://relay.test",
            nostr_auth_relay_lookup_socket=tmp_path / "relays.sock",
        )
    )

    # LOCAL_STDIO_REQUEST's synthetic pubkey must never trigger a lookup.
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        assert adapter._catalog_relays() == ["wss://relay.test"]
    finally:
        set_current_request(None)

    # A real caller whose own relay is already in the base list must not
    # produce a duplicate.
    set_current_request(CALLER_REQUEST)
    try:
        assert adapter._catalog_relays() == ["wss://relay.test"]
    finally:
        set_current_request(None)


def test_catalog_relays_widening_is_best_effort_on_lookup_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import yunohost_mcp.auth.nostr_auth_relay_lookup as relay_lookup_module

    def _raise(pubkey, *, settings):
        raise relay_lookup_module.NostrAuthRelayLookupError("could not reach nostr_auth relay-lookup service")

    monkeypatch.setattr(relay_lookup_module, "lookup_linked_relays", _raise)
    set_current_request(CALLER_REQUEST)
    try:
        adapter = YunohostAdapter(
            Settings(
                fake_yunohost=False,
                catalog_relays="wss://relay.test",
                nostr_auth_relay_lookup_socket=tmp_path / "relays.sock",
            )
        )
        assert adapter._catalog_relays() == ["wss://relay.test"]
    finally:
        set_current_request(None)


def test_catalog_verify_fake_mode_never_needs_publisher_key():
    adapter = YunohostAdapter(Settings(fake_yunohost=True))
    result = adapter.catalog_verify("naddr1qqxyz")
    assert result["valid"] is True


def test_catalog_trusted_publishers_falls_back_to_nostr_catalog_ynh_env_file(tmp_path: Path):
    env_path = tmp_path / "nostr-catalogd.env"
    env_path.write_text("NOSTR_YNH_RELAYS=wss://relay.damus.io\nNOSTR_YNH_TRUSTED_PUBLISHERS=npub1aaa,npub1bbb\n")
    adapter = YunohostAdapter(
        Settings(fake_yunohost=False, catalog_trusted_publishers="", catalog_relays_env_path=env_path)
    )
    assert adapter._catalog_trusted_publishers() == ["npub1aaa", "npub1bbb"]


def test_catalog_trusted_publishers_explicit_override_wins():
    adapter = YunohostAdapter(Settings(fake_yunohost=False, catalog_trusted_publishers="npub1override"))
    assert adapter._catalog_trusted_publishers() == ["npub1override"]


def test_catalog_list_fake_mode_never_contacts_relays():
    adapter = YunohostAdapter(Settings(fake_yunohost=True, catalog_relays="wss://relay.test"))
    result = adapter.catalog_list()
    assert result["fake"] is True
    assert result["relays"] == ["wss://relay.test"]
    assert "example" in result["apps"]


def test_catalog_list_requires_at_least_one_relay():
    adapter = YunohostAdapter(Settings(fake_yunohost=False, catalog_relays="", catalog_relays_env_path=Path("/does/not/exist")))
    with pytest.raises(ValueError, match="catalog_relays"):
        adapter.catalog_list()


@pytest.mark.anyio
async def test_catalog_list_tool_is_read_only_no_confirmation_needed():
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool("catalog_list", {})
            assert result.is_error is not True, result.content
            assert "apps" in result.structured_content
    finally:
        set_current_request(None)


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
