"""Adapter over YunoHost's native Python API.

Per PHASE0_INVESTIGATION.md, the recommended strategy is to import
`yunohost.*` modules directly in-process rather than shelling out to the
`yunohost` CLI or proxying the existing LDAP-cookie-authed `yunohost-api`.

This module is intentionally the *only* place that imports `yunohost.*` or
falls back to fake data — tools/resources should go through `YunohostAdapter`
rather than reaching into `yunohost` themselves, so that:
  - the fake/real switch (Settings.fake_yunohost) has one seam
  - later phases (LDAP context init, locking, recovering @is_unit_operation
    operation ids via _latest_operation_id()) have one place to get right

Phase 4 (v0.1 read-only MVP) implements every read call from PLAN.md's
"Suggested v0.1 scope", mapped 1:1 to the functions found in
PHASE0_INVESTIGATION.md. `diagnosis_run` and `tools_update` are flagged
there as genuinely slow/networked; this phase still calls them
synchronously (the async operation-id pattern is Phase 5, for writes) but
callers should expect these two in particular to take real time against a
live YunoHost.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from yunohost_mcp.config import Settings


class YunohostUnavailableError(RuntimeError):
    """Raised when a real YunoHost call is attempted but yunohost.* can't be imported."""


def _import_attr(module_name: str, attr: str) -> Any:
    try:
        module = importlib.import_module(module_name)
        return getattr(module, attr)
    except ImportError as exc:
        raise YunohostUnavailableError(
            f"{module_name} is not importable on this host; "
            "set YUNOHOST_MCP_FAKE_YUNOHOST=true for local development"
        ) from exc


@dataclass
class YunohostAdapter:
    """Thin wrapper around yunohost.* read operations."""

    settings: Settings

    def server_info(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "yunohost": {"version": "12.0.0", "repo": "stable"},
                "moulinette": {"version": "12.0.0", "repo": "stable"},
                "ssowat": {"version": "12.0.0", "repo": "stable"},
            }
        tools_versions = _import_attr("yunohost.tools", "tools_versions")
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
        diagnosis_show = _import_attr("yunohost.diagnosis", "diagnosis_show")
        return {"fake": False, **diagnosis_show()}

    def apps_list(self, full: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            app = {"id": "nextcloud", "name": "Nextcloud", "version": "28.0.1~ynh1"}
            if full:
                app["description"] = "Self-hosted productivity platform"
            return {"fake": True, "apps": [app]}
        app_list = _import_attr("yunohost.app", "app_list")
        return {"fake": False, **app_list(full=full)}

    def app_info(self, app: str, full: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            info: dict[str, Any] = {"id": app, "name": app, "version": "1.0~ynh1", "upgradable": False}
            if full:
                # Shape matches the real app_info(full=True): permissions
                # live nested under settings["_permissions"], not as a
                # separate top-level key.
                info["settings"] = {
                    "domain": "example.com",
                    "path": f"/{app}",
                    "_permissions": {f"{app}.main": {"allowed": ["all_users"]}},
                }
                info["manifest"] = {"id": app, "version": "1.0~ynh1"}
            return {"fake": True, **info}
        app_info = _import_attr("yunohost.app", "app_info")
        return {"fake": False, **app_info(app, full=full)}

    def diagnosis_run(self, categories: list[str] | None = None, force: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "categories_run": categories or ["ip", "dnsrecords", "services"]}
        # diagnosis_run's *raw* function takes operation_logger as its first
        # argument, but the exported name is wrapped by @is_unit_operation
        # (src/log.py), which constructs and injects its own OperationLogger
        # internally and does NOT expect the caller to pass one - see the
        # "Errata" section of PHASE0_INVESTIGATION.md for how this was
        # originally gotten wrong, and _latest_operation_id()'s docstring for
        # how the id is recovered without one.
        diagnosis_run = _import_attr("yunohost.diagnosis", "diagnosis_run")
        result = diagnosis_run(categories=categories or [], force=force)
        return {"fake": False, "operation_id": _latest_operation_id(), **(result or {})}

    def diagnosis_get(self) -> dict[str, Any]:
        # Same aggregated report as health_check(); kept as a separate
        # adapter method so the two MCP tools stay independently
        # scope-checked even though they call the same YunoHost primitive.
        return self.health_check()

    def services_list(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "services": {
                    "nginx": {"status": "running", "start_on_boot": "enabled"},
                    "yunohost-api": {"status": "running", "start_on_boot": "enabled"},
                },
            }
        service_status = _import_attr("yunohost.service", "service_status")
        return {"fake": False, "services": service_status([])}

    def service_status(self, names: list[str]) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "services": {name: {"status": "running"} for name in names}}
        service_status = _import_attr("yunohost.service", "service_status")
        return {"fake": False, "services": service_status(names)}

    def domains_list(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "domains": ["example.com"], "main": "example.com"}
        domain_list = _import_attr("yunohost.domain", "domain_list")
        return {"fake": False, **domain_list()}

    def users_list(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "users": {"alice": {"fullname": "Alice Example", "mail": "alice@example.com"}}}
        user_list = _import_attr("yunohost.user", "user_list")
        return {"fake": False, **user_list()}

    def backups_list(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "archives": ["20260901-000000"]}
        backup_list = _import_attr("yunohost.backup", "backup_list")
        return {"fake": False, **backup_list()}

    def operations_list(self, limit: int | None = None) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "operation": [
                    {
                        "name": "20260901-120000-app_install",
                        "description": "Install nextcloud",
                        "success": True,
                        "started_at": "2026-09-01T12:00:00",
                    }
                ],
            }
        log_list = _import_attr("yunohost.log", "log_list")
        return {"fake": False, **log_list(limit=limit)}

    def operation_status(self, name: str) -> dict[str, Any]:
        # log_show() is also what backs operation_logs(); this method
        # exists as its own scope-checked MCP tool per PLAN.md's v0.1 list
        # ("operation_status" vs "operation_logs"), both reading the same
        # underlying record.
        return self.operation_logs(name)

    def operation_logs(self, name: str) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "name": name,
                "success": True,
                "started_at": "2026-09-01T12:00:00",
                "log": "fake log content for " + name,
            }
        log_show = _import_attr("yunohost.log", "log_show")
        return {"fake": False, **log_show(name)}

    def updates_check(self) -> dict[str, Any]:
        # Deliberately the no-refresh, cache-only variant: a real network
        # catalog refresh (tools_update()) mutates on-disk cache state and
        # belongs with Phase 5's write tools, not v0.1's read-only scope.
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "apps": [{"id": "nextcloud", "current_version": "28.0.1~ynh1", "new_version": "28.0.2~ynh1"}],
                "system": [],
            }
        tools_update_norefresh = _import_attr("yunohost.tools", "tools_update_norefresh")
        return {"fake": False, **tools_update_norefresh()}

    def plan_app_upgrade(self, app: str) -> dict[str, Any]:
        """Read-only facts for one app's upgrade (PLAN.md Phase 7) - current
        vs. target version, whether it's actually upgradable. Policy
        evaluation (backup/free-space warnings, blocked) is layered on top
        in server.py's plan_app_upgrade tool, not here - this method only
        reports what YunoHost itself knows."""
        updates = self.updates_check()
        match = next((a for a in updates.get("apps", []) if a.get("id") == app), None)
        return {
            "fake": updates.get("fake", False),
            "app": app,
            "upgradable": match is not None,
            "current_version": match.get("current_version") if match else None,
            "target_version": match.get("new_version") if match else None,
        }

    # -- Phase 5/6: writes -------------------------------------------------
    #
    # None of these construct or pass an OperationLogger. Several of the
    # underlying functions (app_install, app_remove, backup_create,
    # tools_upgrade, diagnosis_run) are decorated with @is_unit_operation
    # (src/log.py), which constructs its own OperationLogger internally and
    # prepends it to the call itself - the exported name is the wrapper, not
    # the raw function, so a caller passing one manually corrupts the
    # remaining positional arguments (see PHASE0_INVESTIGATION.md's
    # "Errata" section for exactly how, and why the original version of
    # this file got it wrong). We recover a best-effort operation id
    # afterward via _latest_operation_id() instead.

    def service_restart(self, names: list[str]) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "restarted": names}
        service_restart = _import_attr("yunohost.service", "service_restart")
        service_restart(names)
        return {"fake": False, "restarted": names}

    def backup_create(
        self,
        name: str | None = None,
        description: str | None = None,
        apps: list[str] | None = None,
        system: list[str] | None = None,
    ) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "operation_id": "20260903-000000-backup_create",
                "name": name or "fake-backup",
            }
        backup_create = _import_attr("yunohost.backup", "backup_create")
        result = backup_create(name=name, description=description, apps=apps or [], system=system or [])
        return {"fake": False, "operation_id": _latest_operation_id(), "result": result}

    def app_install(
        self,
        app: str,
        label: str | None = None,
        args: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_install", "app": app}
        app_install = _import_attr("yunohost.app", "app_install")
        result = app_install(app, label=label, args=args, force=force)
        return {"fake": False, "operation_id": _latest_operation_id(), "result": result}

    def app_upgrade(self, app: str | list[str] | None = None, force: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "app": app, "result": "success"}
        # app_upgrade() is not @is_unit_operation-decorated; it builds its
        # own OperationLogger internally, once per app it actually
        # upgrades, so there's no single id to hand back for a multi-app
        # call - the per-app result dict plus operations_list() cover it.
        app_upgrade = _import_attr("yunohost.app", "app_upgrade")
        result = app_upgrade(app=app or [], force=force)
        return {"fake": False, "app": app, "result": result}

    def app_remove(self, app: str, purge: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_remove", "app": app, "purged": purge}
        app_remove = _import_attr("yunohost.app", "app_remove")
        result = app_remove(app, purge=purge)
        return {"fake": False, "operation_id": _latest_operation_id(), "app": app, "result": result}

    def backup_restore(
        self,
        name: str,
        apps: list[str] | None = None,
        system: list[str] | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "name": name, "apps": apps or [], "system": system or []}
        # backup_restore() is not @is_unit_operation-decorated either - no
        # operation id to capture here at all, best-effort or otherwise.
        backup_restore = _import_attr("yunohost.backup", "backup_restore")
        result = backup_restore(name, system=system or [], apps=apps or [], force=force)
        return {"fake": False, "name": name, "result": result}

    def system_upgrade(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-tools_upgrade", "result": "success"}
        tools_upgrade = _import_attr("yunohost.tools", "tools_upgrade")
        result = tools_upgrade(target="system")
        return {"fake": False, "operation_id": _latest_operation_id(), "result": result}


def _latest_operation_id() -> str | None:
    """Best-effort operation id for an @is_unit_operation-wrapped call that
    just returned successfully: its OperationLogger is internal to the
    decorator, never handed back to the caller, so there is no id to
    capture directly. Falls back to "whatever operation log_list() now
    reports as newest" - correct as long as this MCP server's own WriteLock
    (policy/locks.py) is the only thing dispatching writes, since it
    already guarantees at most one write is in flight through this
    process; a concurrent `yunohost` CLI/API write from *outside* this
    server could still race it, making this a best-effort id, not a
    guaranteed-correct one.
    """
    try:
        log_list = _import_attr("yunohost.log", "log_list")
        operations = log_list(limit=1).get("operation", [])
        return operations[0]["name"] if operations else None
    except Exception:  # noqa: BLE001 - never let id-recovery mask the write's own result
        return None
