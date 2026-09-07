from __future__ import annotations

import pytest

from yunohost_mcp.concord_routing import (
    AmbiguousChannelError,
    match_repository_channel,
    match_source_channel,
    normalize_channel_list,
    repository_name,
)


def test_normalize_channel_list_accepts_control_plane_shape():
    payload = {
        "channels": [
            {"channel_id": "ditto-id", "channel_name": " ditto_ynh ", "private": True},
            {"id": "ignored", "name": "missing"},
            "not metadata",
        ]
    }

    assert normalize_channel_list(payload) == [
        {"id": "ditto-id", "name": "ditto_ynh", "private": True, "deleted": False},
        {"id": "ignored", "name": "missing", "private": False, "deleted": False},
    ]


def test_normalize_channel_list_is_safe_for_unexpected_payloads():
    assert normalize_channel_list(None) == []
    assert normalize_channel_list({"messages": []}) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("https://github.com/imattau/ditto_ynh", "ditto_ynh"),
        ("https://github.com/imattau/ditto_ynh.git/", "ditto_ynh"),
        ("/workspace/ditto_ynh", "ditto_ynh"),
    ],
)
def test_repository_name_preserves_repository_convention(source: str, expected: str):
    assert repository_name(source) == expected


def test_repository_name_rejects_empty_source():
    with pytest.raises(ValueError, match="must not be empty"):
        repository_name("  ")


def test_match_source_channel_uses_repository_name_before_package_id():
    match = match_source_channel(
        "https://github.com/imattau/ditto_ynh",
        [
            {"id": "channel-1", "name": "ditto_ynh", "private": False},
            {"id": "channel-2", "name": "ditto", "private": False},
        ],
    )
    assert match is not None
    assert match.channel_id == "channel-1"
    assert match.repository_name == "ditto_ynh"


def test_match_ignores_deleted_and_malformed_channels():
    assert match_repository_channel(
        "ditto_ynh",
        [
            {"id": "deleted", "name": "ditto_ynh", "deleted": True},
            {"name": "ditto_ynh"},
        ],
    ) is None


def test_match_requires_one_exact_name_and_returns_stable_id():
    match = match_repository_channel(
        "Ditto_YNH",
        [{"channel_id": "stable-id", "name": "ditto_ynh", "private": True}],
    )
    assert match is not None
    assert match.channel_id == "stable-id"
    assert match.channel_name == "ditto_ynh"
    assert match.private is True


def test_match_refuses_ambiguous_channels():
    with pytest.raises(AmbiguousChannelError, match="multiple active Concord channels"):
        match_repository_channel(
            "ditto_ynh",
            [
                {"id": "one", "name": "ditto_ynh"},
                {"id": "two", "name": "DITTO_YNH"},
            ],
        )


def test_aliases_are_explicit_only():
    assert match_repository_channel(
        "special_ynh",
        [{"id": "channel-1", "name": "packages"}],
    ) is None
    match = match_repository_channel(
        "special_ynh",
        [{"id": "channel-1", "name": "packages"}],
        aliases={"special_ynh": "packages"},
    )
    assert match is not None
    assert match.channel_id == "channel-1"
