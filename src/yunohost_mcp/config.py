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

    # Same-host Nostr YunoHost catalogue publisher integration.
    catalog_cli_path: Path = Path("/var/lib/nostr-catalogd/nostr-ynh")
    catalog_publisher_key_path: Path = Path("/etc/nostr-catalogd/publisher.key")
    catalog_relays: str = ""
    catalog_cli_timeout_seconds: int = 120
    catalog_require_remote_ref: bool = True

    # HTTP exposure limits. These are deliberately bounded defaults; a
    # deployment can lower them, but should not silently run unbounded.
    max_request_body_bytes: int = 1_048_576
    request_timeout_seconds: int = 120
    max_concurrent_requests: int = 8

    def identity_file_path(self) -> Path:
        """pubkey -> role mapping (Phase 3). A missing file means an empty
        store: deny-by-default, not fail-open."""
        return self.config_dir / "identity.toml"

    def audit_log_path(self) -> Path:
        """JSON-lines audit trail for write tools (Phase 5/10). Created on first write."""
        return self.config_dir / "audit.jsonl"

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


def load_settings() -> Settings:
    return Settings()
