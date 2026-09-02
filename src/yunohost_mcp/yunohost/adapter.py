"""Adapter over YunoHost's native Python API.

Per PHASE0_INVESTIGATION.md, the recommended strategy is to import
`yunohost.*` modules directly in-process rather than shelling out to the
`yunohost` CLI or proxying the existing LDAP-cookie-authed `yunohost-api`.

This module is intentionally the *only* place that imports `yunohost.*` or
falls back to fake data — tools/resources should go through `YunohostAdapter`
rather than reaching into `yunohost` themselves, so that:
  - the fake/real switch (Settings.fake_yunohost) has one seam
  - later phases (operation_logger construction, LDAP context init, locking)
    have one place to get right
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yunohost_mcp.config import Settings


class YunohostUnavailableError(RuntimeError):
    """Raised when a real YunoHost call is attempted but yunohost.* can't be imported."""


@dataclass
class YunohostAdapter:
    """Thin wrapper around yunohost.* read operations.

    Phase 1 only implements the two calls needed to prove the MCP server
    works end to end: tools_versions() (backs server_info) and
    diagnosis_show() (backs health_check). Everything else in PLAN.md's
    v0.1 scope (apps_list, diagnosis_run, services_list, ...) follows in
    later phases, mapped 1:1 to the functions found in
    PHASE0_INVESTIGATION.md.
    """

    settings: Settings

    def server_info(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "yunohost": {"version": "12.0.0", "repo": "stable"},
                "moulinette": {"version": "12.0.0", "repo": "stable"},
                "ssowat": {"version": "12.0.0", "repo": "stable"},
            }

        try:
            from yunohost.tools import tools_versions  # type: ignore[import-not-found]
        except ImportError as exc:
            raise YunohostUnavailableError(
                "yunohost.tools is not importable on this host; "
                "set YUNOHOST_MCP_FAKE_YUNOHOST=true for local development"
            ) from exc

        return {"fake": False, **tools_versions()}

    def health_check(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "categories": [
                    {"id": "ip", "status": "SUCCESS", "summary": "IPv4 and IPv6 reachable"},
                    {"id": "dnsrecords", "status": "SUCCESS", "summary": "DNS records look good"},
                    {"id": "services", "status": "SUCCESS", "summary": "All services running"},
                ],
            }

        try:
            from yunohost.diagnosis import diagnosis_show  # type: ignore[import-not-found]
        except ImportError as exc:
            raise YunohostUnavailableError(
                "yunohost.diagnosis is not importable on this host; "
                "set YUNOHOST_MCP_FAKE_YUNOHOST=true for local development"
            ) from exc

        return {"fake": False, **diagnosis_show()}
