"""Tests for service_logs(): structured systemd journal entries for one
YunoHost-managed service, filling the gap operation_logs()/package_logs()
leave (those only cover formal YunoHost *operations*, never a service's
own raw crash/error output) - see adapter.py's service_logs() docstring
and the cross-agent handoff (Codex) that identified this gap.

Uses a small controllable stub standing in for journalctl (recording the
argv it was invoked with, and emitting fixed `-o json` style output),
mirroring this suite's existing package_lint tests' pattern of pointing
settings at a real, invocable stand-in binary rather than mocking
subprocess.run itself.
"""

from __future__ import annotations

import json
import stat
import sys
import textwrap

import pytest

from yunohost_mcp.config import Settings
from yunohost_mcp.yunohost.adapter import ToolInputError, YunohostAdapter, YunohostUnavailableError


def _write_stub_journalctl(tmp_path, *, argv_file, entries=None, exit_code=0, stderr_text=""):
    entries = entries if entries is not None else [
        {
            "__REALTIME_TIMESTAMP": "1788430200000000",
            "_SYSTEMD_UNIT": "yunohost_mcp.service",
            "PRIORITY": "3",
            "MESSAGE": "something broke",
        },
        {
            "__REALTIME_TIMESTAMP": "1788430260000000",
            "_SYSTEMD_UNIT": "yunohost_mcp.service",
            "PRIORITY": "6",
            "MESSAGE": [104, 105],  # non-UTF8 path: journalctl encodes as byte array
        },
    ]
    script = tmp_path / "fake-journalctl"
    script.write_text(
        textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import json
            import sys

            with open({str(argv_file)!r}, "w") as f:
                json.dump(sys.argv[1:], f)

            sys.stderr.write({stderr_text!r})
            for entry in {entries!r}:
                print(json.dumps(entry))
            sys.exit({exit_code!r})
            """)
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _make_adapter(tmp_path, journalctl_path, *, known_services=("yunohost_mcp",)):
    adapter = YunohostAdapter(
        settings=Settings(fake_yunohost=False, journalctl_path=str(journalctl_path), service_logs_max_lines=2000)
    )
    adapter.services_list = lambda: {"fake": False, "services": {name: {} for name in known_services}}
    return adapter


def test_service_logs_fake_mode():
    adapter = YunohostAdapter(settings=Settings(fake_yunohost=True))
    result = adapter.service_logs("yunohost_mcp")
    assert result["fake"] is True
    assert result["service"] == "yunohost_mcp"
    assert isinstance(result["entries"], list) and result["entries"]


def test_service_logs_rejects_a_service_not_in_services_list(tmp_path):
    argv_file = tmp_path / "argv.json"
    stub = _write_stub_journalctl(tmp_path, argv_file=argv_file)
    adapter = _make_adapter(tmp_path, stub, known_services=("nginx",))

    with pytest.raises(ToolInputError, match="not a known YunoHost-managed service"):
        adapter.service_logs("sshd")

    # Must never even shell out for an unvalidated service name.
    assert not argv_file.exists()


def test_service_logs_normalizes_entries(tmp_path):
    argv_file = tmp_path / "argv.json"
    stub = _write_stub_journalctl(tmp_path, argv_file=argv_file)
    adapter = _make_adapter(tmp_path, stub)

    result = adapter.service_logs("yunohost_mcp")

    assert result["fake"] is False
    assert result["service"] == "yunohost_mcp"
    entries = result["entries"]
    assert len(entries) == 2

    assert entries[0]["priority"] == "err"  # PRIORITY "3" -> "err"
    assert entries[0]["service"] == "yunohost_mcp.service"
    assert entries[0]["message"] == "something broke"
    assert entries[0]["timestamp"] == "2026-09-03T10:10:00+00:00"

    assert entries[1]["priority"] == "info"  # PRIORITY "6" -> "info"
    assert entries[1]["message"] == "hi"  # [104, 105] decoded as bytes


def test_service_logs_passes_filters_through_to_journalctl_argv(tmp_path):
    argv_file = tmp_path / "argv.json"
    stub = _write_stub_journalctl(tmp_path, argv_file=argv_file)
    adapter = _make_adapter(tmp_path, stub)

    adapter.service_logs(
        "yunohost_mcp", since="-1h", until="now", priority="err..emerg", grep="traceback", lines=50
    )

    argv = json.loads(argv_file.read_text())
    assert argv == [
        "-u",
        "yunohost_mcp",
        "--no-pager",
        "-o",
        "json",
        "-n",
        "50",
        "--since",
        "-1h",
        "--until",
        "now",
        "-p",
        "err..emerg",
        "--grep",
        "traceback",
    ]


def test_service_logs_caps_lines_at_the_configured_maximum(tmp_path):
    argv_file = tmp_path / "argv.json"
    stub = _write_stub_journalctl(tmp_path, argv_file=argv_file)
    adapter = YunohostAdapter(
        settings=Settings(fake_yunohost=False, journalctl_path=str(stub), service_logs_max_lines=100)
    )
    adapter.services_list = lambda: {"fake": False, "services": {"yunohost_mcp": {}}}

    adapter.service_logs("yunohost_mcp", lines=999999)

    argv = json.loads(argv_file.read_text())
    assert argv[argv.index("-n") + 1] == "100"


def test_service_logs_raises_on_nonzero_exit(tmp_path):
    argv_file = tmp_path / "argv.json"
    stub = _write_stub_journalctl(
        tmp_path, argv_file=argv_file, entries=[], exit_code=1, stderr_text="Unit foo.service not found."
    )
    adapter = _make_adapter(tmp_path, stub)

    with pytest.raises(YunohostUnavailableError, match="Unit foo.service not found"):
        adapter.service_logs("yunohost_mcp")


def test_service_logs_skips_unparseable_lines(tmp_path, monkeypatch):
    # A stub that emits one valid JSON line and one garbage line - the
    # garbage line must be skipped, not crash the whole call.
    argv_file = tmp_path / "argv.json"
    script = tmp_path / "fake-journalctl-garbage"
    script.write_text(
        textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import json
            import sys
            with open({str(argv_file)!r}, "w") as f:
                json.dump(sys.argv[1:], f)
            print(json.dumps({{"__REALTIME_TIMESTAMP": "1788430200000000", "PRIORITY": "6", "MESSAGE": "ok"}}))
            print("not json at all")
            """)
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    adapter = _make_adapter(tmp_path, script)

    result = adapter.service_logs("yunohost_mcp")
    assert len(result["entries"]) == 1
    assert result["entries"][0]["message"] == "ok"
