"""Policy rules (PLAN.md Phase 6): deterministic, server-side safeguards on
top of scope checks. The caller never decides whether a safeguard applies -
this module does, from policy.toml (or the built-in defaults below if
that file doesn't exist - secure by default, not opt-in).

Rule semantics, matching PLAN.md's example config exactly:
  - require_confirmation: the operation must be preceded by a matching
    confirm_operation() call (policy/confirmation.py) bound to the same
    pubkey, tool, and arguments.
  - require_backup: a recent backup archive must exist. This is a
    deliberately coarse check (any archive newer than max_backup_age, not
    "an archive specifically covering this app") - YunoHost archives don't
    expose per-app coverage cheaply without opening each one, and getting
    this exactly right is future work, not Phase 6's job.
  - minimum_free_space_bytes: checked against the root filesystem via
    shutil.disk_usage, not a YunoHost API - it's a plain, portable disk
    check available whether or not yunohost.* is importable.

  - require_owner_signature (PLAN.md Phase 13): the pending confirmation
    must additionally be approved by a *different* identity holding
    Scope.OWNER_APPROVE (server.py's approve_operation tool) before its
    original requester can execute it - two independently NIP-98-signed
    calls from two different identities, not one caller confirming its
    own request twice. Only meaningful alongside require_confirmation.

Unlike require_confirmation (blockable-but-passable with a confirmation),
require_backup and minimum_free_space are hard requirements: no
confirmation can bypass them. PolicyViolation means "this cannot proceed
right now", not "this needs a human to say yes".
"""

from __future__ import annotations

import re
import shutil
import tomllib
from dataclasses import dataclass
from pathlib import Path


class PolicyConfigError(ValueError):
    """policy.toml is malformed or uses a size/duration string this can't parse."""


class PolicyViolation(RuntimeError):
    """A hard policy requirement (require_backup, minimum_free_space) is unmet."""


@dataclass(frozen=True)
class PolicyRule:
    require_confirmation: bool = False
    require_backup: bool = False
    minimum_free_space_bytes: int | None = None
    max_backup_age_seconds: int | None = None
    require_owner_signature: bool = False


_SIZE_UNITS = {"": 1, "B": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([A-Za-z]*)\s*", value)
    if not match:
        raise PolicyConfigError(f"not a size (e.g. '2GB', '512MB'): {value!r}")
    number, unit = match.groups()
    try:
        multiplier = _SIZE_UNITS[unit.upper()]
    except KeyError:
        raise PolicyConfigError(f"unknown size unit {unit!r} in {value!r}") from None
    return int(number) * multiplier


def _parse_duration(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([A-Za-z]*)\s*", value)
    if not match:
        raise PolicyConfigError(f"not a duration (e.g. '24h', '30m'): {value!r}")
    number, unit = match.groups()
    unit = unit.lower() or "s"
    try:
        multiplier = _DURATION_UNITS[unit]
    except KeyError:
        raise PolicyConfigError(f"unknown duration unit {unit!r} in {value!r}") from None
    return int(number) * multiplier


DEFAULT_POLICY: dict[str, PolicyRule] = {
    "catalog.publish": PolicyRule(require_confirmation=True),
    "apps.upgrade": PolicyRule(require_backup=True, minimum_free_space_bytes=_parse_size("2GB")),
    "apps.remove": PolicyRule(
        require_confirmation=True, require_backup=True, max_backup_age_seconds=_parse_duration("24h")
    ),
    # PLAN.md Phase 13's two highest-risk, already-implemented candidates
    # get owner co-signing by default - the others it names (user deletion,
    # domain removal, firewall/permission changes) aren't implemented as
    # tools yet, and "app removal with data" would need argument-conditional
    # policy (require_owner_signature only when purge=true) this dataclass
    # doesn't support - noted as a real gap, not silently assumed covered.
    "backups.restore": PolicyRule(require_confirmation=True, require_owner_signature=True),
    "system.upgrade": PolicyRule(require_confirmation=True, require_owner_signature=True),
}


def load_policy(path: Path) -> dict[str, PolicyRule]:
    """DEFAULT_POLICY, with any [policy.<key>] sections in `path` overriding
    only the fields they set. A missing file means the defaults apply
    unmodified - this is a safety floor, not a feature you opt into."""
    if not path.exists():
        return dict(DEFAULT_POLICY)

    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise PolicyConfigError(f"{path}: invalid TOML: {exc}") from exc

    rules = dict(DEFAULT_POLICY)
    for key, entry in data.get("policy", {}).items():
        base = rules.get(key, PolicyRule())
        overrides: dict = {}
        if "require_confirmation" in entry:
            overrides["require_confirmation"] = bool(entry["require_confirmation"])
        if "require_backup" in entry:
            overrides["require_backup"] = bool(entry["require_backup"])
        if "minimum_free_space" in entry:
            overrides["minimum_free_space_bytes"] = _parse_size(str(entry["minimum_free_space"]))
        if "max_backup_age" in entry:
            overrides["max_backup_age_seconds"] = _parse_duration(str(entry["max_backup_age"]))
        if "require_owner_signature" in entry:
            overrides["require_owner_signature"] = bool(entry["require_owner_signature"])
        rules[key] = PolicyRule(
            require_confirmation=overrides.get("require_confirmation", base.require_confirmation),
            require_backup=overrides.get("require_backup", base.require_backup),
            minimum_free_space_bytes=overrides.get("minimum_free_space_bytes", base.minimum_free_space_bytes),
            max_backup_age_seconds=overrides.get("max_backup_age_seconds", base.max_backup_age_seconds),
            require_owner_signature=overrides.get("require_owner_signature", base.require_owner_signature),
        )
    return rules


def check_free_space(rule: PolicyRule, *, path: str = "/") -> None:
    if rule.minimum_free_space_bytes is None:
        return
    free = shutil.disk_usage(path).free
    if free < rule.minimum_free_space_bytes:
        raise PolicyViolation(
            f"only {free} bytes free on {path}, policy requires at least {rule.minimum_free_space_bytes}"
        )


def check_recent_backup(rule: PolicyRule, *, archive_created_at: dict[str, float], now: float) -> None:
    """`archive_created_at` maps each archive name to its real creation
    time (yunohost.backup.backup_list(with_info=True)'s info.json
    "created_at" field - see YunohostAdapter.backup_created_at_times()).

    Deliberately NOT parsed from the archive *name*: an earlier version
    of this check assumed every archive name starts with a
    YYYYMMDD-HHMMSS timestamp (true only for an unnamed backup_create()
    call), which meant it could never recognize yunohost's own automatic
    pre-upgrade safety backup - always named
    "<app>-pre-upgrade1"/"<app>-pre-upgrade2" - as satisfying this check,
    making apps.upgrade/apps.remove's "recent backup" requirement
    unsatisfiable via the single most common real-world source of one.
    """
    if not rule.require_backup:
        return
    if not archive_created_at:
        raise PolicyViolation("policy requires a recent backup, but no backup archives exist")

    newest = max(archive_created_at.values())

    if rule.max_backup_age_seconds is not None and (now - newest) > rule.max_backup_age_seconds:
        raise PolicyViolation(
            f"newest backup is {int(now - newest)}s old, policy requires one within {rule.max_backup_age_seconds}s"
        )
