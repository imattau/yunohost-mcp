"""Configuration loading for yunohost-mcp.

Policy config (policy.toml) gets its own loader once Phase 6 lands.
identity.toml (Phase 3) is resolved here via identity_file_path().
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Top-level server settings, overridable via YUNOHOST_MCP_* env vars."""

    model_config = SettingsConfigDict(env_prefix="YUNOHOST_MCP_")

    server_name: str = "yunohost-mcp"

    # Root of the config tree (identity.toml, policy.toml, etc. live here
    # once Phase 3/6 land). Defaults to /etc/yunohost-mcp on a real
    # YunoHost install; overridable for local development.
    config_dir: Path = Field(default=Path("/etc/yunohost-mcp"))

    # When true, the YunoHost adapter layer returns canned/fake data instead
    # of importing yunohost.* modules. Lets the MCP server run and be
    # exercised on a machine without YunoHost installed (e.g. this dev box).
    # Real mode is the safe production default. Tests and local development
    # must opt in explicitly with YUNOHOST_MCP_FAKE_YUNOHOST=true.
    fake_yunohost: bool = False

    # NIP-98 auth (Phase 2), only relevant for the http transport.
    nip98_clock_skew_seconds: int = 60
    nip98_replay_ttl_seconds: int = 300

    # Confirmation tickets (Phase 6) expire after this long if unused.
    confirmation_ttl_seconds: int = 300
    confirmation_store_file: Path | None = None
    package_test_session_ttl_seconds: int = 1800

    # Owner co-signing (Phase 13; owner-approval-plan.md, v1 `solo` only).
    # owner_npub: an explicit owner identity (npub or hex pubkey). A
    # packaged install seeds this from the install-time admin_npub. Left
    # unset, auth/owner.py falls back to "the one identity.toml entry with
    # the administrator role" - ambiguous (zero or several) resolves to no
    # owner, not a guess.
    owner_npub: str | None = None
    # owner_approval_ttl_seconds: separate, longer TTL for confirmation
    # tickets that require owner signature - the requester's original call
    # and the owner's NIP-46 approval are two independent round trips
    # separated by a human opening a signer app, which the default
    # confirmation_ttl_seconds (sized for same-session retries) doesn't
    # allow enough time for.
    owner_approval_ttl_seconds: int = 1800
    # owner_notify_relays (owner-approval-plan.md's "Optional encrypted-DM
    # delivery"): comma-separated relay URLs to publish a best-effort,
    # non-authoritative NIP-17 notification to when a require_owner_
    # signature confirmation is first created - see notify.py. Empty
    # (the default) disables this entirely; approval itself never depends
    # on it (approve_operation is checked independently of whether any
    # notification was ever sent, delivered, or read).
    owner_notify_relays: str = ""
    # owner_push_approval: instead of (or alongside) the DM nudge above,
    # actively request the owner's signature the moment a require_owner_
    # signature confirmation is created - reusing whatever NIP-46 session
    # yunohost-mcp-approve pair already established (config_dir/
    # approve-session.json by default; the same file the ynh packaging's
    # config-panel Pair action writes to, since it runs on this same box).
    # No separate approve_operation call needed if the owner approves via
    # their signer's push prompt: see server.py's _push_owner_approval.
    # Disabled automatically (not an error) whenever no session is paired
    # yet - this is additive to the existing manual approve_operation
    # flow, never a replacement for it, since a signer might be offline,
    # decline, or simply not be paired.
    owner_push_approval_enabled: bool = True
    owner_push_approval_timeout_seconds: int = 90
    owner_push_approval_session_path: Path | None = None

    # Path to a local checkout of github.com/YunoHost/package_linter
    # (package_linter.py at its root). package_lint() is unavailable (not
    # faked, not silently skipped) when this is None - linting is optional
    # tooling, not part of yunohost core, so there's no in-process fallback
    # to reach for the way fake_yunohost covers yunohost.* itself.
    package_linter_path: Path | None = None
    package_linter_timeout_seconds: int = 120
    # An interpreter with package_linter's own deps (jsonschema, toml,
    # packaging, pyparsing) installed - its own venv, typically, not
    # whatever "python3" happens to resolve to on this process's PATH
    # (which, run via `uv run`, is yunohost-mcp's own isolated venv and
    # does NOT have them). An absolute path avoids PATH ambiguity entirely.
    package_linter_python: str = "python3"

    # Optional local Polypack MCP integration.  This is deliberately unset
    # by default: the YunoHost MCP service remains fully functional when the
    # separate polypack-mcp app is not installed or is not configured.  The
    # package's port is allocated by YunoHost, so deployments must provide
    # the actual loopback endpoint rather than relying on a hard-coded port.
    polypack_url: str | None = None
    polypack_timeout_seconds: float = 30.0
    polypack_max_content_chars: int = 100_000
    polypack_max_query_chars: int = 4_000
    polypack_max_response_items: int = 100

    # The *system* python3 (Debian's own, with yunohost/moulinette and
    # their actual apt-installed deps on its path) - used to run specific
    # real yunohost.* calls in a subprocess instead of in-process, when
    # the in-process import would resolve `pydantic` to this venv's own
    # (newer, v2) copy instead of the system's v1 one that some yunohost
    # code (yunohost.utils.form's pydantic v1-style validators, reached
    # e.g. via backup's storage-location settings) is actually written
    # against. Once a `pydantic` module is loaded once in a process every
    # later `import pydantic` anywhere in that same process returns the
    # same cached module (Python's own import system, not something this
    # server can work around at import time) - so in-process coexistence
    # of both pydantic versions is impossible, and a subprocess using an
    # interpreter that never loads this venv's site-packages at all is
    # the only way to actually get pydantic v1's behavior for these
    # specific calls. See yunohost/adapter.py's _call_via_system_python().
    system_python: str = "/usr/bin/python3"
    system_python_timeout_seconds: int = 1800

    # Empty keeps the current in-process adapter behavior. When set, the
    # frontend can delegate registered YunoHost calls to the local broker.
    broker_socket_path: Path | None = None
    identity_backend: str = "toml"
    nostr_auth_lookup_socket: Path | None = None
    nostr_auth_lookup_timeout_seconds: int = 5

    # _catalog_relays()'s optional fourth fallback: widen a catalog search
    # with the *calling* identity's own NIP-65 relay list, via nostr_auth's
    # relay-lookup socket, if it reports that pubkey as linked. None (the
    # default) disables this entirely - same opt-in shape as
    # nostr_auth_lookup_socket above, and deliberately a separate socket
    # setting even though nostr_auth's own default deployment points both
    # at the same shared consumer group, since they're independent
    # services with their own lifecycles.
    nostr_auth_relay_lookup_socket: Path | None = None
    nostr_auth_relay_lookup_timeout_seconds: int = 5

    # Optional bridge to the derivative's signed Nostr operation chain. The
    # agent key is provisioned separately and is never accepted on argv or
    # returned through MCP; unset/disabled keeps the reference backend intact.
    native_control_plane_enabled: bool = False
    native_control_plane_relay: str = "ws://127.0.0.1:4848"
    native_control_plane_agent_key_path: Path = Path("/etc/yunohost-mcp/control-plane-agent.key")

    # service_logs(): structured systemd journal entries for one
    # YunoHost-managed service (see adapter.py). journalctl_path lets a
    # deployment point at a non-default binary; the other two bound a
    # single call's cost/response size the same way max_request_body_bytes
    # etc. do for the HTTP layer generally.
    journalctl_path: str = "journalctl"
    service_logs_timeout_seconds: int = 30
    service_logs_max_lines: int = 2000

    # Read-only incident introspection. These defaults point only at the
    # standard Nginx log directory and keep every response bounded.
    nginx_log_dir: Path = Path("/var/log/nginx")
    nginx_logs_max_lines: int = 2000
    introspection_command_timeout_seconds: int = 15
    introspection_max_output_bytes: int = 256_000
    allow_private_http_probes: bool = False

    # operation_logs()/package_logs(): a real install/upgrade operation's
    # log can run to thousands of lines (full shell traces from every
    # script hook) - returning that by default is a lot of low-signal
    # content for a caller to pay token cost on, on every call, even one
    # that only wanted "did this succeed". Callers that genuinely need the
    # full log still can (operation_logs' tail_lines param, or set this
    # higher/None for "unbounded" - see its docstring for the unrelated
    # yunohost.log.log_show() bug this must stay compatible with).
    operation_logs_default_tail_lines: int = 200

    # Same-host Nostr YunoHost catalogue publisher integration. This
    # deliberately piggybacks on nostr_catalog_ynh rather than duplicating
    # its config: the CLI binary and publisher key already come from that
    # app's install dir, so the relay list should too (single source of
    # truth, editable from nostr_catalog_ynh's own config panel) instead
    # of yunohost-mcp maintaining its own separate, easily-out-of-sync
    # relay setting.
    catalog_cli_path: Path = Path("/var/lib/nostr-catalogd/nostr-ynh")
    catalog_publisher_key_path: Path = Path("/etc/nostr-catalogd/publisher.key")
    # Explicit override; leave empty to fall back to nostr_catalog_ynh's
    # own NOSTR_YNH_RELAYS (see catalog_relays_env_path below).
    catalog_relays: str = ""
    # Same idea as catalog_relays, for the `catalog` CLI subcommand's own
    # --trusted-publishers (catalog_list()): which publisher npubs/hex
    # keys count when the same app id has declarations from more than one
    # publisher. Leave empty to fall back to nostr_catalog_ynh's own
    # NOSTR_YNH_TRUSTED_PUBLISHERS, written to the same env file.
    catalog_trusted_publishers: str = ""
    catalog_relays_env_path: Path = Path("/etc/nostr-catalogd/nostr-catalogd.env")
    catalog_cli_timeout_seconds: int = 120
    catalog_require_remote_ref: bool = True

    # Optional Concord/Armada bot integration. Disabled by default: catalogue
    # publication must never become dependent on announcement delivery. The
    # bot secret and invite are file-backed so they are not passed through MCP
    # calls, logs, or environment values. The eventual adapter must validate
    # ownership and file permissions before reading either file.
    armada_enabled: bool = False
    armada_relays: str = ""
    armada_bot_key_path: Path = Path("/etc/yunohost-mcp/armada-bot.key")
    armada_community_invite_path: Path = Path("/etc/yunohost-mcp/armada-community.invite")
    armada_delivery_store_file: Path | None = None
    armada_timeout_seconds: int = 30
    armada_auto_announce: bool = False

    # HTTP exposure limits. These are deliberately bounded defaults; a
    # deployment can lower them, but should not silently run unbounded.
    max_request_body_bytes: int = 1_048_576
    request_timeout_seconds: int = 120
    max_concurrent_requests: int = 8
    # Canonical externally visible origin for NIP-98 URL binding. Set this
    # behind a reverse proxy so an attacker cannot choose the signed Host.
    public_base_url: str | None = None

    def identity_file_path(self) -> Path:
        """pubkey -> role mapping (Phase 3). A missing file means an empty
        store: deny-by-default, not fail-open."""
        return self.config_dir / "identity.toml"

    def audit_log_path(self) -> Path:
        """JSON-lines audit trail for write tools (Phase 5/10). Created on first write."""
        return self.config_dir / "audit.jsonl"

    def armada_delivery_path(self) -> Path:
        """Durable idempotency store for successful Armada announcements."""
        return self.armada_delivery_store_file or self.config_dir / "armada-deliveries.sqlite3"

    def armada_pending_signature_path(self) -> Path:
        """Short-lived holding area for a split (caller-signed) Concord
        envelope between its *_draft and *_submit calls."""
        return self.config_dir / "armada-pending-signatures.sqlite3"

    def policy_file_path(self) -> Path:
        """Safeguard overrides (Phase 6). A missing file means the built-in
        defaults in policy/rules.py apply unmodified - a safety floor, not
        an opt-in feature."""
        return self.config_dir / "policy.toml"

    def server_identity_path(self) -> Path:
        """This server's own Nostr keypair (Phase 12, minimal slice) - the
        private key file, 0600. Generated on first run if absent."""
        return self.config_dir / "server_identity.key"

    def revoked_delegations_path(self) -> Path:
        """Explicitly-revoked delegation event ids (Phase 11). A missing
        file means nothing has been revoked yet, not "revoke everything"."""
        return self.config_dir / "revoked_delegations.toml"

    def approve_session_path(self) -> Path:
        """Where yunohost-mcp-approve's paired NIP-46 session lives -
        owner_push_approval_session_path if explicitly set, else the same
        default the CLI itself uses when pointed at this server's own
        config_dir (approve.py's default_session_path() falls back to
        ~/.config/yunohost-mcp for a *human's own machine*; this server
        process instead expects the ynh packaging's convention of pairing
        directly into config_dir, since its config-panel actions run on
        this same box - see yunohost_mcp_approve_session_file in the
        packaging repo's _common.sh)."""
        return self.owner_push_approval_session_path or (self.config_dir / "approve-session.json")


def load_settings() -> Settings:
    return Settings()
