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
    assert DEFAULT_POLICY["backups.restore"].require_confirmation is True
    assert DEFAULT_POLICY["system.upgrade"].require_confirmation is True


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
    check_free_space(PolicyRule())  # no minimum_free_space_bytes -> no-op


def test_check_free_space_raises_when_insufficient(tmp_path: Path):
    rule = PolicyRule(minimum_free_space_bytes=10**18)  # absurdly large
    with pytest.raises(PolicyViolation):
        check_free_space(rule, path=str(tmp_path))


def test_check_free_space_passes_when_sufficient(tmp_path: Path):
    rule = PolicyRule(minimum_free_space_bytes=1)
    check_free_space(rule, path=str(tmp_path))


def test_check_recent_backup_skips_when_not_required():
    check_recent_backup(PolicyRule(require_backup=False), archives=[], now=0)


def test_check_recent_backup_raises_when_no_archives():
    with pytest.raises(PolicyViolation):
        check_recent_backup(PolicyRule(require_backup=True), archives=[], now=1_700_000_000)


def test_check_recent_backup_passes_within_max_age():
    now = 1_700_100_000
    import datetime as dt

    fresh = dt.datetime.fromtimestamp(now - 3600, tz=dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    rule = PolicyRule(require_backup=True, max_backup_age_seconds=86400)
    check_recent_backup(rule, archives=[fresh], now=now)


def test_check_recent_backup_raises_when_too_old():
    now = 1_700_100_000
    import datetime as dt

    stale = dt.datetime.fromtimestamp(now - 2 * 86400, tz=dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    rule = PolicyRule(require_backup=True, max_backup_age_seconds=86400)
    with pytest.raises(PolicyViolation):
        check_recent_backup(rule, archives=[stale], now=now)
