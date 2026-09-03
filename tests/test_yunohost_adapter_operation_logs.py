"""Regression test: operation_logs() must always pass an explicit
`number` to yunohost.log.log_show().

yunohost.log.log_show(), called with no `number` at all, takes a
different internal branch (read_file() returning the whole log as one
string) than when a number is given (_tail(), returning a real list of
lines) - then unconditionally does list(logs) on whichever it got. On the
no-number path that explodes the log content into a list of *individual
characters* instead of lines (a real bug in yunohost core itself, not
something fixable from here) - caught live via a cross-agent handoff:
Codex found operation_logs()'s "logs" field coming back character-by-
character while testing this server.
"""

from __future__ import annotations

import types

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import YunohostAdapter


def test_operation_logs_always_passes_an_explicit_number(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def log_show(name, number=None, **_):
        captured["name"] = name
        captured["number"] = number
        return {"name": name, "logs": ["line one", "line two"]}

    yunohost_log = types.ModuleType("yunohost.log")
    yunohost_log.log_show = log_show
    monkeypatch.setitem(__import__("sys").modules, "yunohost.log", yunohost_log)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    result = adapter.operation_logs("20260901-000000-app_install")

    assert captured["number"] is not None
    assert isinstance(captured["number"], int) and captured["number"] > 0
    assert result["logs"] == ["line one", "line two"]


def test_operation_logs_tail_lines_is_passed_through_as_number(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def log_show(name, number=None, **_):
        captured["number"] = number
        return {"name": name, "logs": []}

    yunohost_log = types.ModuleType("yunohost.log")
    yunohost_log.log_show = log_show
    monkeypatch.setitem(__import__("sys").modules, "yunohost.log", yunohost_log)

    adapter = YunohostAdapter(settings=Settings(fake_yunohost=False))
    adapter.operation_logs("20260901-000000-app_install", tail_lines=50)

    assert captured["number"] == 50
