"""End-to-end smoke test: a real MCP client session against yunohost_mcp.server.

Uses the MCP SDK's in-process `Client` (backed by `InMemoryTransport`) so this
exercises the actual MCP protocol (tool listing, tool call, JSON-RPC framing)
rather than just calling the underlying Python functions directly.

This exercises the stdio-equivalent path, which is implicitly fully
trusted (see auth/identity.py's LOCAL_STDIO_REQUEST) — so tests set that
context themselves, the way server.py's stdio branch of main() does.
"""

from __future__ import annotations

import json

import pytest
from mcp.client import Client

from yunohost_mcp.auth.identity import AuthenticatedRequest, IdentityRecord, LOCAL_STDIO_REQUEST, set_current_request
from yunohost_mcp.policy.roles import scopes_for_roles
from yunohost_mcp.server import audit_log, mcp

PHASE5_WRITE_TOOLS = {"service_restart", "backup_create", "app_install", "app_upgrade"}
PHASE6_WRITE_TOOLS = {"app_remove", "backup_restore", "system_upgrade", "domain_add"}
APP_CHANGE_URL_TOOLS = {"app_change_url"}
MIGRATIONS_TOOLS = {"migrations_list", "migrations_state", "migrations_run"}
FIREWALL_TOOLS = {"firewall_list", "firewall_is_open", "firewall_open", "firewall_close", "firewall_reload"}
PHASE7_TOOLS = {"plan_app_upgrade", "execute_plan"}
PHASE8_TOOLS = {
    "package_inspect",
    "package_lint",
    "package_install_test",
    "package_upgrade_test",
    "package_backup_test",
    "package_restore_test",
    "package_change_url_test",
    "package_remove_test",
    "package_logs",
    "package_run_tests",
}
PHASE10_TOOLS = {"audit_list", "audit_get"}
PHASE11_TOOLS = {"server_identity"}
PHASE13_TOOLS = {"approve_operation", "approval_get", "approval_status"}
PHASE14_TOOLS = {"diagnose_app", "validate_server", "safe_upgrade", "repair_app", "test_package"}
USER_MGMT_READ_TOOLS = {"user_group_list", "user_permission_list"}
USER_MGMT_PLAIN_CONFIRM_TOOLS = {"user_create", "user_update", "user_group_create", "user_group_update"}
USER_MGMT_OWNER_COSIGN_TOOLS = {"user_delete", "user_group_delete", "user_permission_add", "user_permission_remove"}

PHASE4_TOOLS = {
    "apps_list",
    "app_info",
    "app_resources",
    "diagnosis_run",
    "diagnosis_get",
    "services_list",
    "service_status",
    "domains_list",
    "users_list",
    "backups_list",
    "operations_list",
    "operation_status",
    "operation_logs",
    "updates_check",
    "updates_refresh",
}


@pytest.fixture(autouse=True)
def local_stdio_identity():
    set_current_request(LOCAL_STDIO_REQUEST)
    yield
    set_current_request(None)


SECOND_ADMIN_REQUEST = AuthenticatedRequest(
    pubkey="second-admin",
    event_id="a" * 64,
    event_created_at=0,
    identity=IdentityRecord(
        pubkey="second-admin", name="second admin", roles=("administrator",), scopes=scopes_for_roles(("administrator",))
    ),
)


@pytest.fixture(autouse=True)
def configured_owner(monkeypatch: pytest.MonkeyPatch):
    """v1 `solo` profile (owner-approval-plan.md): approve_operation checks
    the approver against one configured owner. Tests configure SECOND_ADMIN_
    REQUEST's pubkey as that owner - no on-disk identity.toml/YUNOHOST_MCP_
    OWNER_NPUB needed - by patching server.get_owner_pubkey() directly,
    the same seam server.py itself calls through."""
    from yunohost_mcp import server as server_module

    monkeypatch.setattr(server_module, "get_owner_pubkey", lambda: SECOND_ADMIN_REQUEST.pubkey)


async def _approve_as_second_admin(client: Client, confirmation_id: str) -> None:
    """Owner co-signing (Phase 13) - swap in the configured owner identity
    (configured_owner fixture) for one call, then restore LOCAL_STDIO_
    REQUEST so the rest of the test proceeds as before."""
    set_current_request(SECOND_ADMIN_REQUEST)
    try:
        result = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
        assert result.is_error is not True, result.content
    finally:
        set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_list_tools_exposes_all_v01_read_tools():
    async with Client(mcp) as client:
        result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        expected = (
            {"server_info", "health_check", "whoami"}
            | PHASE4_TOOLS
            | PHASE5_WRITE_TOOLS
            | PHASE6_WRITE_TOOLS
            | APP_CHANGE_URL_TOOLS
            | MIGRATIONS_TOOLS
            | FIREWALL_TOOLS
            | PHASE7_TOOLS
            | PHASE8_TOOLS
            | PHASE10_TOOLS
            | PHASE11_TOOLS
            | PHASE13_TOOLS
            | PHASE14_TOOLS
            | USER_MGMT_READ_TOOLS
            | USER_MGMT_PLAIN_CONFIRM_TOOLS
            | USER_MGMT_OWNER_COSIGN_TOOLS
        )
        assert expected <= names


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("apps_list", {}),
        ("app_info", {"app": "nextcloud"}),
        ("app_resources", {"app": "nextcloud"}),
        ("diagnosis_run", {}),
        ("diagnosis_get", {}),
        ("services_list", {}),
        ("service_status", {"names": ["nginx"]}),
        ("domains_list", {}),
        ("users_list", {}),
        ("user_group_list", {}),
        ("user_permission_list", {}),
        ("backups_list", {}),
        ("operations_list", {}),
        ("operation_status", {"name": "20260901-120000-app_install"}),
        ("operation_logs", {"name": "20260901-120000-app_install"}),
        ("updates_check", {}),
        ("updates_refresh", {}),
        ("migrations_list", {}),
        ("migrations_state", {}),
        ("firewall_list", {}),
        ("firewall_is_open", {"port": 443, "protocol": "tcp"}),
    ],
)
async def test_phase4_tool_succeeds_for_local_stdio_identity(tool: str, args: dict):
    async with Client(mcp) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error is not True, result.content
        assert result.structured_content is not None
        assert result.structured_content.get("fake") is True


@pytest.mark.anyio
async def test_phase4_tool_denied_for_identity_without_scope():
    # A "readonly" role has apps.read but not, say, backups.read revoked here
    # by using an identity with *no* roles at all: zero scopes, so every
    # scope-gated tool must be denied.
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("apps_list", {})
        assert result.is_error is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("service_restart", {"names": ["nginx"]}),
        ("backup_create", {"name": "test-backup"}),
        ("app_install", {"app": "nextcloud"}),
        ("app_upgrade", {"app": "nextcloud"}),
    ],
)
async def test_phase5_write_tool_succeeds_and_is_audited(tool: str, args: dict):
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error is not True, result.content
        assert result.structured_content is not None
        assert result.structured_content.get("fake") is True

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["caller"] == "local-stdio"
    assert entry["result"] == "success"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("backup_restore", {"name": "20260901-000000"}),
        ("system_upgrade", {}),
        ("migrations_run", {}),
        ("firewall_open", {"port": 8080, "protocol": "tcp"}),
        ("firewall_close", {"port": 8080, "protocol": "tcp"}),
        ("firewall_reload", {}),
    ],
)
async def test_phase6_confirmable_write_requires_then_accepts_confirmation(tool: str, args: dict):
    async with Client(mcp) as client:
        first = await client.call_tool(tool, args)
        assert first.is_error is not True, first.content
        plan_response = first.structured_content
        assert plan_response["confirmation_required"] is True
        assert "operation_plan" in plan_response
        assert plan_response["owner_signature_required"] is True  # both tools default to Phase 13 co-signing
        confirmation_id = plan_response["confirmation_id"]

        # Calling again with the SAME args but no confirmation_id issues a
        # brand new ticket rather than executing - it never silently proceeds.
        second = await client.call_tool(tool, args)
        assert second.structured_content["confirmation_required"] is True
        assert second.structured_content["confirmation_id"] != confirmation_id

        # Not yet owner-approved: the original ticket must still refuse to execute.
        not_yet_approved = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert not_yet_approved.is_error is True

        await _approve_as_second_admin(client, confirmation_id)

        confirmed = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert confirmed.is_error is not True, confirmed.content
        assert confirmed.structured_content.get("fake") is True
        assert "confirmation_required" not in confirmed.structured_content


@pytest.mark.anyio
async def test_domain_add_requires_then_accepts_a_plain_confirmation():
    # domains.write has require_confirmation but not require_owner_signature
    # (unlike backup_restore/system_upgrade above) - a single caller's own
    # confirmation_id round trip is enough, no second identity needed.
    async with Client(mcp) as client:
        first = await client.call_tool("domain_add", {"domain": "new.example.com"})
        assert first.is_error is not True, first.content
        plan_response = first.structured_content
        assert plan_response["confirmation_required"] is True
        assert plan_response["owner_signature_required"] is False
        confirmation_id = plan_response["confirmation_id"]

        confirmed = await client.call_tool(
            "domain_add", {"domain": "new.example.com", "confirmation_id": confirmation_id}
        )
        assert confirmed.is_error is not True, confirmed.content
        assert confirmed.structured_content.get("fake") is True
        assert confirmed.structured_content["domain"] == "new.example.com"
        assert "confirmation_required" not in confirmed.structured_content


@pytest.mark.anyio
async def test_app_change_url_requires_then_accepts_a_plain_confirmation():
    # apps.change_url has require_confirmation but not require_owner_signature
    # or require_backup - same single-caller confirmation shape as domain_add
    # above, deliberately lighter than apps.remove (see policy/rules.py).
    args = {"app": "mangatsu", "domain": "manga.example.com", "path": "/"}
    async with Client(mcp) as client:
        first = await client.call_tool("app_change_url", args)
        assert first.is_error is not True, first.content
        plan_response = first.structured_content
        assert plan_response["confirmation_required"] is True
        assert plan_response["owner_signature_required"] is False
        confirmation_id = plan_response["confirmation_id"]

        confirmed = await client.call_tool("app_change_url", {**args, "confirmation_id": confirmation_id})
        assert confirmed.is_error is not True, confirmed.content
        assert confirmed.structured_content.get("fake") is True
        assert confirmed.structured_content["app"] == "mangatsu"
        assert confirmed.structured_content["domain"] == "manga.example.com"
        assert "confirmation_required" not in confirmed.structured_content


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        (
            "user_create",
            {"username": "alice", "domain": "example.com", "password": "hunter2", "fullname": "Alice Example"},
        ),
        ("user_update", {"username": "alice", "fullname": "Alice New"}),
        ("user_group_create", {"groupname": "editors"}),
        ("user_group_update", {"groupname": "editors", "add": ["alice"]}),
    ],
)
async def test_user_mgmt_plain_confirmable_write_requires_then_accepts_confirmation(tool: str, args: dict):
    # users.write has require_confirmation but not require_owner_signature -
    # same single-caller confirmation shape as domain_add above.
    async with Client(mcp) as client:
        first = await client.call_tool(tool, args)
        assert first.is_error is not True, first.content
        plan_response = first.structured_content
        assert plan_response["confirmation_required"] is True
        assert plan_response["owner_signature_required"] is False
        confirmation_id = plan_response["confirmation_id"]

        confirmed = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert confirmed.is_error is not True, confirmed.content
        assert confirmed.structured_content.get("fake") is True
        assert "confirmation_required" not in confirmed.structured_content


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("user_delete", {"username": "alice"}),
        ("user_group_delete", {"groupname": "editors"}),
        ("user_permission_add", {"permission": "myapp.main", "names": ["alice"]}),
        ("user_permission_remove", {"permission": "myapp.main", "names": ["alice"]}),
    ],
)
async def test_user_mgmt_owner_cosign_write_requires_then_accepts_confirmation(tool: str, args: dict):
    # users.delete / users.permissions both require owner co-signature -
    # same two-identity shape as backup_restore/system_upgrade above
    # (PLAN.md Phase 13 names "user deletion" and "permission changes" as
    # candidates for this).
    async with Client(mcp) as client:
        first = await client.call_tool(tool, args)
        assert first.is_error is not True, first.content
        plan_response = first.structured_content
        assert plan_response["confirmation_required"] is True
        assert plan_response["owner_signature_required"] is True
        confirmation_id = plan_response["confirmation_id"]

        not_yet_approved = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert not_yet_approved.is_error is True

        await _approve_as_second_admin(client, confirmation_id)

        confirmed = await client.call_tool(tool, {**args, "confirmation_id": confirmation_id})
        assert confirmed.is_error is not True, confirmed.content
        assert confirmed.structured_content.get("fake") is True
        assert "confirmation_required" not in confirmed.structured_content


@pytest.mark.anyio
async def test_user_create_password_is_redacted_from_confirmation_plan_and_audit_log():
    # password must never appear in the echoed operation_plan (returned to
    # the caller) or the audit log entry - redaction.py's is_sensitive_key
    # substring-matches "password" in both the plan_builder's own fields and
    # the raw kwargs audit_log.record() stores.
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    args = {"username": "alice", "domain": "example.com", "password": "hunter2", "fullname": "Alice Example"}
    async with Client(mcp) as client:
        first = await client.call_tool("user_create", args)
        assert "hunter2" not in json.dumps(first.structured_content)
        confirmation_id = first.structured_content["confirmation_id"]

        confirmed = await client.call_tool("user_create", {**args, "confirmation_id": confirmation_id})
        assert "hunter2" not in json.dumps(confirmed.structured_content)

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert "hunter2" not in "\n".join(new_lines)


@pytest.mark.anyio
async def test_phase6_confirmation_rejected_for_mismatched_arguments():
    async with Client(mcp) as client:
        first = await client.call_tool("backup_restore", {"name": "archive-a"})
        confirmation_id = first.structured_content["confirmation_id"]

        # Same confirmation_id, different archive name - must not execute.
        mismatched = await client.call_tool(
            "backup_restore", {"name": "archive-b", "confirmation_id": confirmation_id}
        )
        assert mismatched.is_error is True


@pytest.mark.anyio
async def test_phase6_confirmation_is_one_shot():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]
        await _approve_as_second_admin(client, confirmation_id)

        ok = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert ok.is_error is not True

        reused = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert reused.is_error is True


@pytest.mark.anyio
async def test_phase13_execute_without_owner_approval_is_denied():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        result = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase13_non_owner_cannot_approve_even_its_own_request():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        # LOCAL_STDIO_REQUEST is the requester, and (per configured_owner)
        # is not the configured owner - approving must fail regardless of
        # whether it's also the requester.
        result = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase13_owner_may_approve_and_consume_its_own_request():
    """v1 `solo` profile (owner-approval-plan.md): when the owner is also
    the requester (no delegated agent in front of them), approval is still
    a separate signed call, but does not require a different pubkey."""
    set_current_request(SECOND_ADMIN_REQUEST)
    try:
        async with Client(mcp) as client:
            first = await client.call_tool("system_upgrade", {})
            confirmation_id = first.structured_content["confirmation_id"]

            approve = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
            assert approve.is_error is not True, approve.content

            second = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
            assert second.is_error is not True, second.content
    finally:
        set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_phase13_approve_operation_denied_for_non_administrator():
    package_developer = AuthenticatedRequest(
        pubkey="dev-pubkey",
        event_id="d" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="dev-pubkey",
            name="dev-agent",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
        ),
    )
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        set_current_request(package_developer)
        try:
            result = await client.call_tool("approve_operation", {"confirmation_id": confirmation_id})
            assert result.is_error is True
        finally:
            set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_phase13_approve_operation_is_audited():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
        await _approve_as_second_admin(client, confirmation_id)
        new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]

    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "owner.approve"
    assert entry["caller"] == "second-admin"
    assert entry["result"] == "success"


@pytest.mark.anyio
async def test_phase13_approved_confirmation_can_still_be_used_for_a_second_call_attempt():
    # Approving doesn't consume the ticket - the agent may need more than
    # one attempt (e.g. a transient failure) before it actually executes,
    # as long as it's still the same confirmation_id/arguments.
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]
        await _approve_as_second_admin(client, confirmation_id)

        # Re-approving an already-approved ticket is fine (idempotent from
        # the store's perspective - it's still "different identity than
        # requester", just re-stamping the same approval).
        await _approve_as_second_admin(client, confirmation_id)

        result = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert result.is_error is not True


@pytest.mark.anyio
async def test_phase13_approved_write_records_approved_by_in_its_own_audit_entry():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]
        await _approve_as_second_admin(client, confirmation_id)

        existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
        result = await client.call_tool("system_upgrade", {"confirmation_id": confirmation_id})
        assert result.is_error is not True, result.content
        new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]

    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "system.upgrade"
    assert entry["caller"] == "local-stdio"
    assert entry["approved_by"] == "second-admin"


@pytest.mark.anyio
async def test_phase13_write_not_requiring_owner_signature_has_no_approved_by():
    # domains.write requires a plain confirmation but not owner signature -
    # its audit entry should never carry an approved_by.
    async with Client(mcp) as client:
        first = await client.call_tool("domain_add", {"domain": "no-owner-sig.example.com"})
        confirmation_id = first.structured_content["confirmation_id"]

        existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
        result = await client.call_tool(
            "domain_add", {"domain": "no-owner-sig.example.com", "confirmation_id": confirmation_id}
        )
        assert result.is_error is not True, result.content
        new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]

    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["approved_by"] is None


@pytest.mark.anyio
async def test_approval_get_visible_to_requester():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        result = await client.call_tool("approval_get", {"confirmation_id": confirmation_id})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["confirmation_id"] == confirmation_id
        assert data["tool"] == "system.upgrade"
        assert data["operation_hash"] == first.structured_content["operation_hash"]
        assert data["requester_pubkey"] == "local-stdio"
        assert data["approved"] is False
        assert data["approved_by"] is None


@pytest.mark.anyio
async def test_approval_get_visible_to_owner_even_when_not_the_requester():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        set_current_request(SECOND_ADMIN_REQUEST)
        try:
            result = await client.call_tool("approval_get", {"confirmation_id": confirmation_id})
            assert result.is_error is not True, result.content
            assert result.structured_content["requester_pubkey"] == "local-stdio"
        finally:
            set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_approval_get_denied_for_unrelated_identity():
    package_developer = AuthenticatedRequest(
        pubkey="dev-pubkey",
        event_id="d" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="dev-pubkey",
            name="dev-agent",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
        ),
    )
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        set_current_request(package_developer)
        try:
            result = await client.call_tool("approval_get", {"confirmation_id": confirmation_id})
            assert result.is_error is True
        finally:
            set_current_request(LOCAL_STDIO_REQUEST)


@pytest.mark.anyio
async def test_approval_status_reflects_approval_state():
    async with Client(mcp) as client:
        first = await client.call_tool("system_upgrade", {})
        confirmation_id = first.structured_content["confirmation_id"]

        before = await client.call_tool("approval_status", {"confirmation_id": confirmation_id})
        assert before.structured_content == {
            "confirmation_id": confirmation_id,
            "approved": False,
            "expires_at": first.structured_content["expires_at"],
        }

        await _approve_as_second_admin(client, confirmation_id)

        after = await client.call_tool("approval_status", {"confirmation_id": confirmation_id})
        assert after.structured_content["approved"] is True


@pytest.mark.anyio
async def test_phase14_diagnose_app():
    async with Client(mcp) as client:
        result = await client.call_tool("diagnose_app", {"app": "nextcloud"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["app"] == "nextcloud"
        assert "app_info" in data
        assert "diagnosis" in data


@pytest.mark.anyio
async def test_phase14_validate_server():
    async with Client(mcp) as client:
        result = await client.call_tool("validate_server", {})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert "server" in data and "diagnosis" in data and "services" in data


@pytest.mark.anyio
async def test_phase14_safe_upgrade_runs_full_workflow_and_is_audited():
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        result = await client.call_tool("safe_upgrade", {"app": "nextcloud"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["passed"] is True
        assert [s["step"] for s in data["steps"]][:4] == ["pre_diagnosis", "inspect_app", "backup", "upgrade"]

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "apps.upgrade"
    assert entry["result"] == "success"


@pytest.mark.anyio
async def test_phase14_safe_upgrade_blocked_by_free_space_policy(monkeypatch: pytest.MonkeyPatch):
    from yunohost_mcp import server as server_module

    def huge_minimum(*args, **kwargs):
        raise server_module.PolicyViolation("not enough free space")

    monkeypatch.setattr(server_module, "check_free_space", huge_minimum)
    async with Client(mcp) as client:
        result = await client.call_tool("safe_upgrade", {"app": "nextcloud"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase14_repair_app():
    async with Client(mcp) as client:
        result = await client.call_tool("repair_app", {"app": "nextcloud"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["strategy"] == "conservative"
        assert "diagnosis_before" in data and "diagnosis_after" in data


@pytest.mark.anyio
async def test_phase14_repair_app_rejects_unknown_strategy():
    async with Client(mcp) as client:
        result = await client.call_tool("repair_app", {"app": "nextcloud", "strategy": "aggressive"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase14_test_package_matches_package_run_tests():
    async with Client(mcp) as client:
        result = await client.call_tool("test_package", {"source": "/tmp/example_ynh"})
        assert result.is_error is not True, result.content
        assert result.structured_content["passed"] is True


@pytest.mark.anyio
async def test_phase14_composite_tools_denied_for_identity_without_scope():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        for tool, args in [
            ("diagnose_app", {"app": "nextcloud"}),
            ("validate_server", {}),
            ("safe_upgrade", {"app": "nextcloud"}),
            ("repair_app", {"app": "nextcloud"}),
            ("test_package", {"source": "/tmp/example_ynh"}),
        ]:
            result = await client.call_tool(tool, args)
            assert result.is_error is True, f"{tool} should have been denied"


@pytest.mark.anyio
async def test_phase6_app_remove_blocked_by_stale_backup_policy():
    # Fake backups_list() returns a single, deliberately old archive
    # ("20260901-000000") - older than apps.remove's default 24h max age -
    # so app_remove should be blocked by the hard policy check before it
    # ever gets to the confirmation step.
    async with Client(mcp) as client:
        result = await client.call_tool("app_remove", {"app": "nextcloud"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_policy_violation_surfaces_its_real_message_not_a_generic_crash():
    # Regression: PolicyViolation (and ScopeError, ConfirmationError) used
    # to propagate as a raw, unrecognized exception - the MCP SDK then
    # reported only a generic "Error executing tool X" with no indication
    # of *why*, indistinguishable from a genuine server crash, diagnosable
    # only by reading this server's own systemd journal. See
    # policy/enforcement.py's translate_known_errors.
    async with Client(mcp) as client:
        result = await client.call_tool("app_remove", {"app": "nextcloud"})
        assert result.is_error is True
        assert "policy requires one within" in str(result.content)


@pytest.mark.anyio
async def test_scope_denial_surfaces_its_real_message_not_a_generic_crash():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("apps_list", {})
        assert result.is_error is True
        assert "lacks required scope" in str(result.content)


@pytest.mark.anyio
async def test_execute_plan_policy_violation_surfaces_its_real_message(monkeypatch: pytest.MonkeyPatch):
    # execute_plan re-checks apps.upgrade policy directly in its own body
    # (state may have drifted since plan_app_upgrade), not through
    # @require_confirmation's own `checks=` mechanism - translate_known_errors
    # must still catch it, since it wraps the whole tool body.
    from yunohost_mcp import server as server_module

    async with Client(mcp) as client:
        plan = await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
        plan_id = plan.structured_content["plan_id"]

        def now_blocked(*args, **kwargs):
            raise server_module.PolicyViolation("newest backup is too old")

        monkeypatch.setattr(server_module, "check_recent_backup", now_blocked)
        result = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert result.is_error is True
        assert "newest backup is too old" in str(result.content)


@pytest.mark.anyio
async def test_tool_input_error_surfaces_its_real_message_not_a_generic_crash():
    # Regression: adapter.py's ToolInputError (deliberate caller-input
    # validation - a bad catalog source, a missing required ref, ...) used
    # to be a bare ValueError, not one of translate_known_errors's caught
    # types - "Error executing tool X" with no indication of why, caught
    # live when catalog_publish_plan was called with a remote source and
    # no --ref. _validate_catalog_source() runs even in fake mode (before
    # the fake_yunohost short-circuit), so this needs no adapter mocking.
    async with Client(mcp) as client:
        result = await client.call_tool(
            "catalog_publish_plan", {"source": "https://github.com/example/example_ynh"}
        )
        assert result.is_error is True
        assert "an explicit ref is required for remote catalogue sources" in str(result.content)


@pytest.mark.anyio
async def test_service_logs_is_registered_and_callable():
    # Fills a real gap: operation_logs()/package_logs() only cover formal
    # YunoHost *operations*, never a service's own raw crash/error output -
    # see adapter.py's service_logs() docstring and the cross-agent
    # handoff (Codex) that identified it.
    async with Client(mcp) as client:
        result = await client.call_tool("service_logs", {"service": "yunohost_mcp"})
        assert result.is_error is not True, result.content
        data = result.structured_content
        assert data["service"] == "yunohost_mcp"
        assert isinstance(data["entries"], list) and data["entries"]
        assert set(data["entries"][0]) == {"timestamp", "service", "priority", "message"}


@pytest.mark.anyio
async def test_phase7_plan_then_execute_upgrades_the_app():
    async with Client(mcp) as client:
        plan = await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
        assert plan.is_error is not True, plan.content
        data = plan.structured_content
        assert data["app"] == "nextcloud"
        assert data["upgradable"] is True
        assert data["blocked"] is False
        plan_id = data["plan_id"]

        executed = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert executed.is_error is not True, executed.content
        assert executed.structured_content["app"] == "nextcloud"


@pytest.mark.anyio
async def test_phase7_plan_app_upgrade_does_not_write_audit_entry():
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
    new_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    assert new_lines == existing_lines


@pytest.mark.anyio
async def test_phase7_execute_plan_rejects_unknown_plan_id():
    async with Client(mcp) as client:
        result = await client.call_tool("execute_plan", {"plan_id": "plan-does-not-exist"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase7_execute_plan_is_one_shot():
    async with Client(mcp) as client:
        plan = await client.call_tool("plan_app_upgrade", {"app": "nextcloud"})
        plan_id = plan.structured_content["plan_id"]

        first = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert first.is_error is not True

        second = await client.call_tool("execute_plan", {"plan_id": plan_id})
        assert second.is_error is True


@pytest.mark.anyio
async def test_phase6_write_tool_denied_for_identity_without_scope():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("system_upgrade", {})
        assert result.is_error is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("package_inspect", {"source": "/tmp/example_ynh"}),
        ("package_lint", {"source": "/tmp/example_ynh"}),
        ("package_install_test", {"source": "/tmp/example_ynh"}),
        ("package_upgrade_test", {"app": "example", "source": "/tmp/example_ynh"}),
        ("package_backup_test", {"app": "example"}),
        ("package_restore_test", {"app": "example", "archive_name": "package-test-example"}),
        ("package_change_url_test", {"app": "example", "domain": "new.example.com", "path": "/"}),
        ("package_remove_test", {"app": "example"}),
        ("package_logs", {"operation": "20260901-120000-app_install"}),
        ("package_run_tests", {"source": "/tmp/example_ynh"}),
    ],
)
async def test_phase8_package_tool_succeeds_for_local_stdio_identity(tool: str, args: dict):
    async with Client(mcp) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error is not True, result.content
        assert result.structured_content is not None
        assert result.structured_content.get("fake") is True


@pytest.mark.anyio
async def test_phase8_package_run_tests_writes_one_audit_entry_for_the_whole_cycle():
    existing_lines = audit_log.path.read_text().splitlines() if audit_log.path.exists() else []
    async with Client(mcp) as client:
        result = await client.call_tool("package_run_tests", {"source": "/tmp/example_ynh"})
        assert result.is_error is not True
        assert result.structured_content["passed"] is True

    new_lines = audit_log.path.read_text().splitlines()[len(existing_lines) :]
    assert len(new_lines) == 1
    entry = json.loads(new_lines[0])
    assert entry["tool"] == "packages.test"
    assert entry["result"] == "success"


@pytest.mark.anyio
async def test_phase8_package_test_tool_denied_for_identity_without_scope():
    no_scopes = AuthenticatedRequest(
        pubkey="deadbeef",
        event_id="e" * 64,
        event_created_at=0,
        identity=IdentityRecord(pubkey="deadbeef", name="no-roles", roles=(), scopes=scopes_for_roles(())),
    )
    set_current_request(no_scopes)
    async with Client(mcp) as client:
        result = await client.call_tool("package_install_test", {"source": "/tmp/example_ynh"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase8_package_developer_role_can_test_but_not_administer():
    developer = AuthenticatedRequest(
        pubkey="feedface",
        event_id="f" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="feedface", name="dev-agent", roles=("package-developer",), scopes=scopes_for_roles(("package-developer",))
        ),
    )
    set_current_request(developer)
    async with Client(mcp) as client:
        install = await client.call_tool("package_install_test", {"source": "/tmp/example_ynh"})
        assert install.is_error is not True, install.content

        # package-developer does not grant system.upgrade.
        denied = await client.call_tool("system_upgrade", {})
        assert denied.is_error is True


@pytest.mark.anyio
async def test_server_info_returns_fake_version_data():
    async with Client(mcp) as client:
        result = await client.call_tool("server_info", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data is not None
        assert data["fake"] is True
        assert "yunohost" in data


@pytest.mark.anyio
async def test_health_check_returns_fake_diagnosis_categories():
    async with Client(mcp) as client:
        result = await client.call_tool("health_check", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data is not None
        assert data["fake"] is True
        assert len(data["categories"]) > 0


@pytest.mark.anyio
async def test_whoami_reports_local_stdio_identity():
    async with Client(mcp) as client:
        result = await client.call_tool("whoami", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data is not None
        assert data["authenticated"] is True
        assert data["pubkey"] == "local-stdio"
        assert "administrator" in data["roles"]


@pytest.mark.anyio
async def test_server_identity_tool_returns_npub_and_pubkey():
    async with Client(mcp) as client:
        result = await client.call_tool("server_identity", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data["npub"].startswith("npub1")
        assert len(data["pubkey"]) == 64

        # Calling it again returns the *same* identity (lazy singleton,
        # not regenerated per call).
        again = await client.call_tool("server_identity", {})
        assert again.structured_content == data


@pytest.mark.anyio
async def test_phase9_tool_response_is_redacted_end_to_end(monkeypatch: pytest.MonkeyPatch):
    """A secret-shaped field anywhere in a tool's real return value must
    never reach the MCP client - proves @redact_response actually runs on
    the full protocol path (structured_content), not just as a unit test
    of the decorator in isolation."""
    from yunohost_mcp import server as server_module

    def leaky_server_info():
        return {
            "fake": True,
            "yunohost": {"version": "12.0.0"},
            "db_password": "s3cr3t-should-not-leak",
            "settings": {"ldap_password": "also-secret", "domain": "example.com"},
        }

    monkeypatch.setattr(server_module.adapter, "server_info", leaky_server_info)

    async with Client(mcp) as client:
        result = await client.call_tool("server_info", {})
        assert result.is_error is not True
        data = result.structured_content
        assert data["db_password"] == "[REDACTED]"
        assert data["settings"]["ldap_password"] == "[REDACTED]"
        assert data["settings"]["domain"] == "example.com"
        assert data["yunohost"]["version"] == "12.0.0"

        # Also check the text content mirror the framework generates - a
        # naive fix that only redacted structured_content and not the text
        # representation would still leak the secret there.
        text_blob = " ".join(getattr(c, "text", "") for c in result.content)
        assert "s3cr3t-should-not-leak" not in text_blob
        assert "also-secret" not in text_blob


@pytest.mark.anyio
async def test_phase10_audit_list_and_get_administrator_only():
    async with Client(mcp) as client:
        install = await client.call_tool("app_install", {"app": "nextcloud"})
        assert install.is_error is not True

        listed = await client.call_tool("audit_list", {"limit": 1})
        assert listed.is_error is not True
        entries = listed.structured_content["entries"]
        assert len(entries) == 1
        assert entries[0]["tool"] == "apps.install"
        audit_id = entries[0]["audit_id"]

        got = await client.call_tool("audit_get", {"audit_id": audit_id})
        assert got.is_error is not True
        assert got.structured_content["audit_id"] == audit_id
        assert got.structured_content["tool"] == "apps.install"


@pytest.mark.anyio
async def test_phase10_audit_get_unknown_id_errors():
    async with Client(mcp) as client:
        result = await client.call_tool("audit_get", {"audit_id": "mcp-does-not-exist"})
        assert result.is_error is True


@pytest.mark.anyio
async def test_phase10_audit_tools_denied_for_non_administrator_roles():
    developer = AuthenticatedRequest(
        pubkey="feedface",
        event_id="f" * 64,
        event_created_at=0,
        identity=IdentityRecord(
            pubkey="feedface",
            name="dev-agent",
            roles=("package-developer",),
            scopes=scopes_for_roles(("package-developer",)),
        ),
    )
    set_current_request(developer)
    async with Client(mcp) as client:
        result = await client.call_tool("audit_list", {})
        assert result.is_error is True


@pytest.fixture
def anyio_backend():
    return "asyncio"
