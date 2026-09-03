from __future__ import annotations

import json
from pathlib import Path

from yunohost_mcp.audit.log import AuditLog


def test_record_writes_one_json_line(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    audit_id = log.record(
        tool="apps.install",
        arguments={"app": "nextcloud"},
        caller_pubkey="deadbeef",
        decision="allowed",
        result="success",
        yunohost_operation="20260903-000000-app_install",
    )
    lines = log.path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["audit_id"] == audit_id
    assert entry["tool"] == "apps.install"
    assert entry["arguments"] == {"app": "nextcloud"}
    assert entry["yunohost_operation"] == "20260903-000000-app_install"


def test_record_appends(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record(tool="a", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    log.record(tool="b", arguments={}, caller_pubkey="x", decision="allowed", result="error", error="boom")
    lines = log.path.read_text().strip().splitlines()
    assert len(lines) == 2


def test_record_redacts_known_secret_keys(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record(
        tool="users.write",
        arguments={"username": "alice", "password": "hunter2", "nested": {"api_key": "abc123"}},
        caller_pubkey="x",
        decision="allowed",
        result="success",
    )
    entry = json.loads(log.path.read_text().strip())
    assert entry["arguments"]["username"] == "alice"
    assert entry["arguments"]["password"] == "[REDACTED]"
    assert entry["arguments"]["nested"]["api_key"] == "[REDACTED]"


def test_creates_parent_directory(tmp_path: Path):
    log = AuditLog(path=tmp_path / "nested" / "dir" / "audit.jsonl")
    log.record(tool="a", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    assert log.path.exists()
