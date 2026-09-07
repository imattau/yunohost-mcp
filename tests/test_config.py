from pathlib import Path

from yunohost_mcp.config import Settings


def test_armada_is_disabled_and_file_backed_by_default():
    settings = Settings()

    assert settings.armada_enabled is False
    assert settings.armada_relays == ""
    assert settings.armada_bot_key_path == Path("/etc/yunohost-mcp/armada-bot.key")
    assert settings.armada_community_invite_path == Path("/etc/yunohost-mcp/armada-community.invite")


def test_armada_settings_can_be_overridden_without_secret_values():
    settings = Settings(
        armada_enabled=True,
        armada_relays="wss://relay.example",
        armada_bot_key_path=Path("/run/secrets/armada.key"),
        armada_community_invite_path=Path("/run/secrets/armada.invite"),
        armada_timeout_seconds=12,
    )

    assert settings.armada_enabled is True
    assert settings.armada_relays == "wss://relay.example"
    assert settings.armada_bot_key_path == Path("/run/secrets/armada.key")
    assert settings.armada_timeout_seconds == 12
