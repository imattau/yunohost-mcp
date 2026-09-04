from __future__ import annotations

from pathlib import Path

import pytest

from yunohost_mcp.policy.rules import (
    DEFAULT_POLICY,
    PolicyConfigError,
    PolicyRule,
    PolicyViolation,
    _parse_duration,
    _parse_size,
    check_free_space,
    check_recent_backup,
    load_policy,
)


def test_parse_size_units():
    assert _parse_size("2GB") == 2_000_000_000
    assert _parse_size("512MB") == 512_000_000
    assert _parse_size("100") == 100


def test_parse_size_rejects_garbage():
    with pytest.raises(PolicyConfigError):
        _parse_size("not-a-size")


def test_parse_duration_units():
    assert _parse_duration("24h") == 86400
    assert _parse_duration("30m") == 1800
    assert _parse_duration("1d") == 86400
    assert _parse_duration("3600s") == 3600


def test_default_policy_matches_plan_examples():
    assert DEFAULT_POLICY["apps.upgrade"].require_backup is True
    assert DEFAULT_POLICY["apps.upgrade"].minimum_free_space_bytes == 2_000_000_000
    assert DEFAULT_POLICY["apps.remove"].require_confirmation is True
    assert DEFAULT_POLICY["apps.remove"].require_backup is True
    assert DEFAULT_POLICY["apps.remove"].max_backup_age_seconds == 86400
    assert DEFAULT_POLICY["apps.change_url"].require_confirmation is True
    assert DEFAULT_POLICY["apps.change_url"].require_backup is False
    assert DEFAULT_POLICY["backups.restore"].require_confirmation is True
    assert DEFAULT_POLICY["system.upgrade"].require_confirmation is True
    assert DEFAULT_POLICY["system.migrate"].require_confirmation is True
    assert DEFAULT_POLICY["system.migrate"].require_owner_signature is True
    assert DEFAULT_POLICY["firewall.write"].require_confirmation is True
    assert DEFAULT_POLICY["firewall.write"].require_owner_signature is True


def test_missing_policy_file_yields_defaults(tmp_path: Path):
    rules = load_policy(tmp_path / "nope.toml")
    assert rules == DEFAULT_POLICY


def test_policy_file_overrides_only_given_fields(tmp_path: Path):
    path = tmp_path / "policy.toml"
    path.write_text(
        """
[policy."apps.remove"]
require_confirmation = false
"""
    )
    rules = load_policy(path)
    assert rules["apps.remove"].require_confirmation is False
    # untouched fields keep their default
    assert rules["apps.remove"].require_backup is True
    assert rules["apps.remove"].max_backup_age_seconds == 86400
    # other keys are unaffected
    assert rules["backups.restore"] == DEFAULT_POLICY["backups.restore"]


def test_policy_file_can_define_a_new_key(tmp_path: Path):
    path = tmp_path / "policy.toml"
    path.write_text(
        """
[policy."apps.install"]
require_confirmation = true
minimum_free_space = "1GB"
"""
    )
    rules = load_policy(path)
    assert rules["apps.install"].require_confirmation is True
    assert rules["apps.install"].minimum_free_space_bytes == 1_000_000_000


def test_malformed_policy_toml_raises(tmp_path: Path):
    path = tmp_path / "policy.toml"
    path.write_text("not [valid toml")
    with pytest.raises(PolicyConfigError):
        load_policy(path)


def test_check_free_space_passes_when_no_minimum_set():
    check_free_space(PolicyRule(), free_bytes=0)  # no minimum_free_space_bytes -> no-op


def test_check_free_space_raises_when_insufficient():
    rule = PolicyRule(minimum_free_space_bytes=10**18)  # absurdly large
    with pytest.raises(PolicyViolation):
        check_free_space(rule, free_bytes=1_000)


def test_check_free_space_passes_when_sufficient():
    rule = PolicyRule(minimum_free_space_bytes=1)
    check_free_space(rule, free_bytes=1_000_000)


def test_check_recent_backup_skips_when_not_required():
    check_recent_backup(PolicyRule(require_backup=False), archive_created_at={}, now=0)


def test_check_recent_backup_raises_when_no_archives():
    with pytest.raises(PolicyViolation):
        check_recent_backup(PolicyRule(require_backup=True), archive_created_at={}, now=1_700_000_000)


def test_check_recent_backup_passes_within_max_age():
    now = 1_700_100_000
    rule = PolicyRule(require_backup=True, max_backup_age_seconds=86400)
    check_recent_backup(rule, archive_created_at={"20260901-000000": now - 3600}, now=now)


def test_check_recent_backup_raises_when_too_old():
    now = 1_700_100_000
    rule = PolicyRule(require_backup=True, max_backup_age_seconds=86400)
    with pytest.raises(PolicyViolation):
        check_recent_backup(rule, archive_created_at={"20260801-000000": now - 2 * 86400}, now=now)


def test_check_recent_backup_passes_for_a_pre_upgrade_named_archive():
    # Regression: yunohost's own automatic pre-upgrade safety backup is
    # always named "<app>-pre-upgrade1"/"<app>-pre-upgrade2" - never a
    # YYYYMMDD-HHMMSS timestamp. An earlier version of this check parsed
    # dates from archive *names* and could never recognize this as
    # "recent", making apps.upgrade's own safety backup insufficient to
    # satisfy its own policy. archive_created_at (real info.json
    # metadata, not the name) must not have that blind spot.
    now = 1_700_100_000
    rule = PolicyRule(require_backup=True, max_backup_age_seconds=86400)
    check_recent_backup(rule, archive_created_at={"nextcloud-pre-upgrade2": now - 60}, now=now)


def test_check_recent_backup_uses_the_newest_of_several_archives():
    now = 1_700_100_000
    rule = PolicyRule(require_backup=True, max_backup_age_seconds=86400)
    check_recent_backup(
        rule,
        archive_created_at={
            "nextcloud-pre-upgrade1": now - 30 * 86400,  # stale
            "mcp-test-backup": now - 60,  # recent
        },
        now=now,
    )
