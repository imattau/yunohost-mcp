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


def test_record_can_bind_a_broker_request(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record(
        tool="app.upgrade",
        arguments={"app": "nextcloud"},
        caller_pubkey="agent",
        decision="allowed",
        result="success",
        request_id="request-1",
        execution_context="broker",
    )
    entry = json.loads(log.path.read_text().strip())
    assert entry["request_id"] == "request-1"
    assert entry["execution_context"] == "broker"


def test_list_returns_newest_first(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    first_id = log.record(tool="a", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    second_id = log.record(tool="b", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    entries = log.list()
    assert [e["audit_id"] for e in entries] == [second_id, first_id]


def test_list_respects_limit(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    for i in range(5):
        log.record(tool=f"tool-{i}", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    entries = log.list(limit=2)
    assert len(entries) == 2
    assert entries[0]["tool"] == "tool-4"
    assert entries[1]["tool"] == "tool-3"


def test_list_on_missing_file_returns_empty(tmp_path: Path):
    log = AuditLog(path=tmp_path / "does-not-exist.jsonl")
    assert log.list() == []


def test_get_finds_entry_by_id(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record(tool="a", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    target_id = log.record(tool="b", arguments={"app": "nextcloud"}, caller_pubkey="x", decision="allowed", result="success")
    log.record(tool="c", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    entry = log.get(target_id)
    assert entry is not None
    assert entry["tool"] == "b"
    assert entry["arguments"] == {"app": "nextcloud"}


def test_get_returns_none_for_unknown_id(tmp_path: Path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record(tool="a", arguments={}, caller_pubkey="x", decision="allowed", result="success")
    assert log.get("mcp-does-not-exist") is None
