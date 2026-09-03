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
    fake_yunohost: bool = True

    # NIP-98 auth (Phase 2), only relevant for the http transport.
    nip98_clock_skew_seconds: int = 60
    nip98_replay_ttl_seconds: int = 300

    def identity_file_path(self) -> Path:
        """pubkey -> role mapping (Phase 3). A missing file means an empty
        store: deny-by-default, not fail-open."""
        return self.config_dir / "identity.toml"

    def audit_log_path(self) -> Path:
        """JSON-lines audit trail for write tools (Phase 5/10). Created on first write."""
        return self.config_dir / "audit.jsonl"


def load_settings() -> Settings:
    return Settings()
