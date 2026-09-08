from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from coincurve import PrivateKey, PublicKeyXOnly
from mcp.client import Client

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.config import Settings
from yunohost_mcp.auth.identity import AuthenticatedRequest, IdentityRecord, LOCAL_STDIO_REQUEST, set_current_request
from yunohost_mcp.concord_announcement_publish import AnnouncementPublishResult
from yunohost_mcp.concord_announcements import build_announcement_draft
from yunohost_mcp.concord_bundle import validate_invite_bundle
from yunohost_mcp.concord_credentials import CredentialFileError
from yunohost_mcp.concord_transport import RelayPublishResult
from yunohost_mcp.policy.roles import scopes_for_roles
from yunohost_mcp.server import mcp
import yunohost_mcp.server as server_module
import yunohost_mcp.yunohost.adapter as adapter_module
from yunohost_mcp.yunohost.adapter import YunohostAdapter

CALLER_PUBKEY = "b" * 64
CALLER_REQUEST = AuthenticatedRequest(pubkey=CALLER_PUBKEY, event_id="e" * 64, event_created_at=0)


def _invite_bundle():
    owner = "a" * 64
    salt = "b" * 64
    return validate_invite_bundle(
        {
            "community_id": hashlib.sha256(b"concord/community" + bytes.fromhex(owner + salt)).hexdigest(),
            "owner": owner,
            "owner_salt": salt,
            "community_root": "c" * 64,
            "root_epoch": 2,
            "control_pk": "d" * 64,
            "relays": ["wss://relay.example"],
            "channels": [{"id": "e" * 64, "epoch": 1, "name": "ditto_ynh"}],
        }
    )


def _channel_rumor():
    content = '{"name":"ditto_ynh","private":false}'
    channel = "e" * 64
    return {
        "id": "a" * 64,
        "pubkey": "a" * 64,
        "created_at": 1,
        "kind": 3308,
        "tags": [["vsk", "2"], ["eid", channel], ["ev", "1"]],
        "content": content,
    }


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
async def test_catalog_announce_is_optional_and_disabled_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(server_module.settings, "armada_enabled", False)
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "catalog_announce",
                {"source": "https://github.com/example/ditto_ynh", "catalogue_publication": "{}"},
            )
            assert result.is_error is not True, result.content
            assert result.structured_content == {
                "status": "disabled",
                "warning": "Armada announcements are disabled",
            }
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_armada_join_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(server_module.settings, "armada_enabled", False)
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool("armada_join", {})
            assert result.is_error is not True, result.content
            assert result.structured_content["status"] == "disabled"
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_announce_requires_armada_write_scope():
    readonly = AuthenticatedRequest(
        pubkey="readonly-announcer",
        event_id="r" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="readonly-announcer",
            name="readonly announcer",
            roles=("readonly",),
            scopes=scopes_for_roles(("readonly",)),
        ),
    )
    set_current_request(readonly)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "catalog_announce",
                {"source": "ditto_ynh", "catalogue_publication": "{}"},
            )
            assert result.is_error is True
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_announce_enabled_path_is_composed_without_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    draft = build_announcement_draft(
        "https://github.com/example/ditto_ynh",
        {"published": True},
    )
    expected = AnnouncementPublishResult(
        status="published",
        draft=draft,
        publication=RelayPublishResult(event_id="e" * 64, relays=("wss://relay.test",)),
    )

    async def fake_load_bundle(_invite_url, **_kwargs):
        return object()

    async def fake_load_control(_bundle, **_kwargs):
        return []

    async def fake_publish(**_kwargs):
        return expected

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")
    monkeypatch.setattr(server_module, "load_bot_private_key", lambda _path: object())
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "load_control_rumors", fake_load_control)
    monkeypatch.setattr(server_module, "publish_package_announcement", fake_publish)

    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "catalog_announce",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            assert result.is_error is not True, result.content
            assert result.structured_content == {
                "status": "published",
                "draft": draft.__dict__,
                "publication": {"event_id": "e" * 64, "relays": ["wss://relay.test"]},
            }
            duplicate = await client.call_tool(
                "catalog_announce",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            assert duplicate.is_error is not True, duplicate.content
            assert duplicate.structured_content["status"] == "already_published"
            assert duplicate.structured_content["publication"]["event_id"] == "e" * 64
            status = await client.call_tool(
                "catalog_announcement_status",
                {"idempotency_key": draft.idempotency_key},
            )
            assert status.is_error is not True, status.content
            assert status.structured_content["status"] == "published"
            assert status.structured_content["event_id"] == "e" * 64
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_announce_uses_the_caller_identity_armada_key_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """An identity.toml entry with its own armada_key_path must announce
    under that key, not the shared settings.armada_bot_key_path - otherwise
    every agent's announcement is indistinguishable from the bot's."""
    draft = build_announcement_draft("https://github.com/example/ditto_ynh", {"published": True})
    expected = AnnouncementPublishResult(
        status="published",
        draft=draft,
        publication=RelayPublishResult(event_id="e" * 64, relays=("wss://relay.test",)),
    )
    agent_key_path = tmp_path / "agent-a.key"
    seen_paths: list[Path] = []

    async def fake_load_bundle(_invite_url, **_kwargs):
        return object()

    async def fake_load_control(_bundle, **_kwargs):
        return []

    async def fake_publish(**_kwargs):
        return expected

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")
    monkeypatch.setattr(server_module.settings, "armada_bot_key_path", tmp_path / "shared-bot.key")

    def fake_load_bot_private_key(path: Path):
        seen_paths.append(path)
        return object()

    monkeypatch.setattr(server_module, "load_bot_private_key", fake_load_bot_private_key)
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "load_control_rumors", fake_load_control)
    monkeypatch.setattr(server_module, "publish_package_announcement", fake_publish)

    agent_request = AuthenticatedRequest(
        pubkey="agent-a",
        event_id="a" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="agent-a",
            name="agent a",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
            armada_key_path=agent_key_path,
        ),
    )
    set_current_request(agent_request)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "catalog_announce",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            assert result.is_error is not True, result.content
            assert result.structured_content["status"] == "published"
    finally:
        set_current_request(None)

    assert seen_paths == [agent_key_path]


@pytest.mark.anyio
async def test_catalog_announce_falls_back_to_the_shared_bot_key_without_an_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """An identity with no armada_key_path (or no identity at all, e.g. the
    stdio transport) must keep announcing under the shared bot key - the
    per-identity override is opt-in, not a breaking default change."""
    draft = build_announcement_draft("https://github.com/example/ditto_ynh", {"published": True})
    expected = AnnouncementPublishResult(
        status="published",
        draft=draft,
        publication=RelayPublishResult(event_id="e" * 64, relays=("wss://relay.test",)),
    )
    shared_key_path = tmp_path / "shared-bot.key"
    seen_paths: list[Path] = []

    async def fake_load_bundle(_invite_url, **_kwargs):
        return object()

    async def fake_load_control(_bundle, **_kwargs):
        return []

    async def fake_publish(**_kwargs):
        return expected

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")
    monkeypatch.setattr(server_module.settings, "armada_bot_key_path", shared_key_path)

    def fake_load_bot_private_key(path: Path):
        seen_paths.append(path)
        return object()

    monkeypatch.setattr(server_module, "load_bot_private_key", fake_load_bot_private_key)
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "load_control_rumors", fake_load_control)
    monkeypatch.setattr(server_module, "publish_package_announcement", fake_publish)

    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "catalog_announce",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            assert result.is_error is not True, result.content
            assert result.structured_content["status"] == "published"
    finally:
        set_current_request(None)

    assert seen_paths == [shared_key_path]


@pytest.mark.anyio
async def test_catalog_announce_reports_missing_configuration_as_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")

    def missing_key(_path):
        raise CredentialFileError("Concord bot credential file is unavailable")

    monkeypatch.setattr(server_module, "load_bot_private_key", missing_key)
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            result = await client.call_tool(
                "catalog_announce",
                {"source": "ditto_ynh", "catalogue_publication": '{"published": true}'},
            )
            assert result.is_error is not True, result.content
            assert result.structured_content == {
                "status": "unavailable",
                "warning": "Concord bot credential file is unavailable",
            }
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_publish_requires_confirmation_then_executes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    owner = AuthenticatedRequest(
        pubkey="catalog-owner", event_id="o" * 64, event_created_at=0,
        identity=IdentityRecord(pubkey="catalog-owner", name="catalog owner", roles=("administrator",), scopes=scopes_for_roles(("administrator",))),
    )
    monkeypatch.setattr("yunohost_mcp.server.get_owner_pubkey", lambda: owner.pubkey)
    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_auto_announce", True)
    monkeypatch.setattr(
        server_module,
        "_catalog_announce_impl",
        lambda source, publication: {"status": "published", "source": source},
    )
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            planned = await client.call_tool("catalog_publish_plan", {"source": str(tmp_path)})
            assert planned.is_error is not True
            plan_id = planned.structured_content["plan_id"]

            pending = await client.call_tool("catalog_publish", {"plan_id": plan_id})
            assert pending.is_error is not True
            assert pending.structured_content["confirmation_required"] is True
            assert pending.structured_content["owner_signature_required"] is True

            set_current_request(owner)
            approved = await client.call_tool("approve_operation", {"confirmation_id": pending.structured_content["confirmation_id"]})
            assert approved.is_error is not True
            set_current_request(LOCAL_STDIO_REQUEST)

            published = await client.call_tool(
                "catalog_publish",
                {
                    "plan_id": plan_id,
                    "confirmation_id": pending.structured_content["confirmation_id"],
                },
            )
            assert published.is_error is not True
            assert published.structured_content["published"] is True
            assert published.structured_content["announcement"]["status"] == "published"
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_publish_with_ci_result_attests_alongside_the_declaration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The plan->confirm->publish round trip must carry ci_result through
    correctly - this is what actually exercises the confirmation store's
    arguments_hash check (create-time and consume-time arguments must be
    byte-for-byte the same JSON, including the nested ci_result object) -
    not just that individual functions accept the parameter."""
    owner = AuthenticatedRequest(
        pubkey="catalog-owner-2", event_id="p" * 64, event_created_at=0,
        identity=IdentityRecord(pubkey="catalog-owner-2", name="catalog owner", roles=("administrator",), scopes=scopes_for_roles(("administrator",))),
    )
    monkeypatch.setattr("yunohost_mcp.server.get_owner_pubkey", lambda: owner.pubkey)
    ci_result = {
        "schema": 1,
        "app_id": "example",
        "repository": "https://github.com/example/app_ynh",
        "commit": "a" * 40,
        "manifest": "sha256:" + "0" * 64,
        "content": "sha256:" + "1" * 64,
        "checks": {"yunohost_lint": "pass"},
        "result": "pass",
    }
    set_current_request(LOCAL_STDIO_REQUEST)
    try:
        async with Client(mcp) as client:
            planned = await client.call_tool(
                "catalog_publish_plan",
                {"source": str(tmp_path), "ci_result": ci_result, "ci_provider": "github-actions", "ci_ref": "https://example/run/1"},
            )
            assert planned.is_error is not True
            plan_id = planned.structured_content["plan_id"]
            assert planned.structured_content["attestation"]["event"]["kind"] == 30080

            pending = await client.call_tool("catalog_publish", {"plan_id": plan_id})
            assert pending.structured_content["confirmation_required"] is True

            set_current_request(owner)
            approved = await client.call_tool("approve_operation", {"confirmation_id": pending.structured_content["confirmation_id"]})
            assert approved.is_error is not True
            set_current_request(LOCAL_STDIO_REQUEST)

            published = await client.call_tool(
                "catalog_publish",
                {"plan_id": plan_id, "confirmation_id": pending.structured_content["confirmation_id"]},
            )
            assert published.is_error is not True, published.structured_content
            assert published.structured_content["published"] is True
            assert published.structured_content["attestation"]["published"] is True
            assert published.structured_content["attestation"]["event"]["kind"] == 30080
    finally:
        set_current_request(None)


def test_catalog_publish_plan_echoes_ci_result_for_the_later_publish_call(tmp_path: Path):
    """catalog_publish reads ci_result/ci_provider/ci_ref back out of the
    stored plan (not fresh caller input) - this is the wiring that must
    round-trip, or a real publish would silently drop the attestation."""
    adapter = YunohostAdapter(Settings(fake_yunohost=True, catalog_relays="wss://relay.test"))
    ci_result = {"schema": 1, "app_id": "example"}
    plan = adapter.catalog_publish_plan(
        str(tmp_path),
        ci_result=ci_result,
        ci_provider="github-actions",
        ci_ref="https://example/run/2",
    )
    assert plan["ci_result"] == ci_result
    assert plan["ci_provider"] == "github-actions"
    assert plan["ci_ref"] == "https://example/run/2"
    assert plan["attestation"]["event"]["kind"] == 30080


def _agent_request(pubkey: str) -> AuthenticatedRequest:
    return AuthenticatedRequest(
        pubkey=pubkey,
        event_id="d" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey=pubkey,
            name="agent",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
        ),
    )


@pytest.mark.anyio
async def test_catalog_announce_draft_then_submit_publishes_under_the_callers_own_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """The whole point of the split tools: no bot key or armada_key_path is
    ever loaded here - the caller signs the seal with a key only it holds,
    and catalog_announce_submit must still route/publish/record delivery
    exactly like the bot-key path does."""
    agent_key = PrivateKey(b"k" * 32)
    agent_pubkey = PublicKeyXOnly.from_valid_secret(agent_key.secret).format().hex()
    published: list[tuple[object, list[str]]] = []

    async def fake_load_bundle(_invite_url, **_kwargs):
        return _invite_bundle()

    async def fake_load_control(_bundle, **_kwargs):
        return [_channel_rumor()]

    async def fake_publish(event, relays, **_kwargs):
        published.append((event, relays))
        return RelayPublishResult(event_id=event.id, relays=tuple(relays))

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")
    monkeypatch.setattr(server_module.settings, "config_dir", tmp_path)
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "load_control_rumors", fake_load_control)
    monkeypatch.setattr(server_module, "publish_signed_event", fake_publish)

    set_current_request(_agent_request(agent_pubkey))
    try:
        async with Client(mcp) as client:
            draft = await client.call_tool(
                "catalog_announce_draft",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            assert draft.is_error is not True, draft.content
            assert draft.structured_content["status"] == "draft_ready"
            draft_id = draft.structured_content["draft_id"]
            unsigned = draft.structured_content["unsigned_event"]
            assert unsigned["pubkey"] == agent_pubkey

            signed = sign_event(
                agent_key,
                pubkey=unsigned["pubkey"],
                kind=unsigned["kind"],
                tags=unsigned["tags"],
                content=unsigned["content"],
                created_at=unsigned["created_at"],
            )
            submitted = await client.call_tool(
                "catalog_announce_submit",
                {"draft_id": draft_id, "signed_event": json.dumps(signed.model_dump())},
            )
            assert submitted.is_error is not True, submitted.content
            assert submitted.structured_content["status"] == "published"
            assert submitted.structured_content["publication"]["event_id"]
            assert len(published) == 1

            # Single-use: resubmitting the same draft_id must fail, not double-publish.
            resubmit = await client.call_tool(
                "catalog_announce_submit",
                {"draft_id": draft_id, "signed_event": json.dumps(signed.model_dump())},
            )
            assert resubmit.is_error is True
            assert len(published) == 1
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_announce_submit_rejects_a_draft_issued_to_a_different_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    agent_key = PrivateKey(b"k" * 32)
    agent_pubkey = PublicKeyXOnly.from_valid_secret(agent_key.secret).format().hex()
    other_pubkey = PublicKeyXOnly.from_valid_secret(PrivateKey(b"j" * 32).secret).format().hex()

    async def fake_load_bundle(_invite_url, **_kwargs):
        return _invite_bundle()

    async def fake_load_control(_bundle, **_kwargs):
        return [_channel_rumor()]

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")
    monkeypatch.setattr(server_module.settings, "config_dir", tmp_path)
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "load_control_rumors", fake_load_control)

    set_current_request(_agent_request(agent_pubkey))
    try:
        async with Client(mcp) as client:
            draft = await client.call_tool(
                "catalog_announce_draft",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            draft_id = draft.structured_content["draft_id"]
            unsigned = draft.structured_content["unsigned_event"]
    finally:
        set_current_request(None)

    signed = sign_event(
        agent_key,
        pubkey=unsigned["pubkey"],
        kind=unsigned["kind"],
        tags=unsigned["tags"],
        content=unsigned["content"],
        created_at=unsigned["created_at"],
    )
    set_current_request(_agent_request(other_pubkey))
    try:
        async with Client(mcp) as client:
            submitted = await client.call_tool(
                "catalog_announce_submit",
                {"draft_id": draft_id, "signed_event": json.dumps(signed.model_dump())},
            )
            assert submitted.is_error is True
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_catalog_announce_submit_rejects_a_tampered_signature(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    agent_key = PrivateKey(b"k" * 32)
    agent_pubkey = PublicKeyXOnly.from_valid_secret(agent_key.secret).format().hex()

    async def fake_load_bundle(_invite_url, **_kwargs):
        return _invite_bundle()

    async def fake_load_control(_bundle, **_kwargs):
        return [_channel_rumor()]

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "armada_delivery_store_file", tmp_path / "deliveries.sqlite3")
    monkeypatch.setattr(server_module.settings, "config_dir", tmp_path)
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "load_control_rumors", fake_load_control)

    set_current_request(_agent_request(agent_pubkey))
    try:
        async with Client(mcp) as client:
            draft = await client.call_tool(
                "catalog_announce_draft",
                {
                    "source": "https://github.com/example/ditto_ynh",
                    "catalogue_publication": '{"published": true}',
                },
            )
            draft_id = draft.structured_content["draft_id"]
            unsigned = draft.structured_content["unsigned_event"]

            signed = sign_event(
                agent_key,
                pubkey=unsigned["pubkey"],
                kind=unsigned["kind"],
                tags=unsigned["tags"],
                content="something else entirely",
                created_at=unsigned["created_at"],
            )
            submitted = await client.call_tool(
                "catalog_announce_submit",
                {"draft_id": draft_id, "signed_event": json.dumps(signed.model_dump())},
            )
            assert submitted.is_error is True
    finally:
        set_current_request(None)


@pytest.mark.anyio
async def test_armada_join_draft_then_submit_publishes_under_the_callers_own_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    agent_key = PrivateKey(b"k" * 32)
    agent_pubkey = PublicKeyXOnly.from_valid_secret(agent_key.secret).format().hex()
    published: list[tuple[object, list[str]]] = []

    async def fake_load_bundle(_invite_url, **_kwargs):
        return _invite_bundle()

    async def fake_publish(event, relays, **_kwargs):
        published.append((event, relays))
        return RelayPublishResult(event_id=event.id, relays=tuple(relays))

    async def fake_fetch_guestbook(_pubkey, _relays, **_kwargs):
        return []

    monkeypatch.setattr(server_module.settings, "armada_enabled", True)
    monkeypatch.setattr(server_module.settings, "config_dir", tmp_path)
    monkeypatch.setattr(server_module, "read_credential_file", lambda _path, *, label: "https://invite.test")
    monkeypatch.setattr(server_module, "load_invite_bundle", fake_load_bundle)
    monkeypatch.setattr(server_module, "publish_signed_event", fake_publish)
    monkeypatch.setattr(server_module, "fetch_guestbook_events", fake_fetch_guestbook)

    set_current_request(_agent_request(agent_pubkey))
    try:
        async with Client(mcp) as client:
            draft = await client.call_tool("armada_join_draft", {})
            assert draft.is_error is not True, draft.content
            assert draft.structured_content["status"] == "draft_ready"
            draft_id = draft.structured_content["draft_id"]
            unsigned = draft.structured_content["unsigned_event"]
            assert unsigned["pubkey"] == agent_pubkey

            signed = sign_event(
                agent_key,
                pubkey=unsigned["pubkey"],
                kind=unsigned["kind"],
                tags=unsigned["tags"],
                content=unsigned["content"],
                created_at=unsigned["created_at"],
            )
            submitted = await client.call_tool(
                "armada_join_submit",
                {"draft_id": draft_id, "signed_event": json.dumps(signed.model_dump())},
            )
            assert submitted.is_error is not True, submitted.content
            assert submitted.structured_content["status"] in {"published", "published_unverified"}
            assert len(published) == 1
    finally:
        set_current_request(None)
