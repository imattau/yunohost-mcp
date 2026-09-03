"""Configuration loading for yunohost-mcp.

Phase 1 scope: just enough to run the server locally over stdio. Auth
(identity.toml, Phase 3) and policy (policy.toml, Phase 6) config get their
own loaders as those phases land.
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


def load_settings() -> Settings:
    return Settings()
