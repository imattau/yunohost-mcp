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
                info["settings"] = {"domain": "example.com", "path": f"/{app}"}
                info["permissions"] = {f"{app}.main": {"allowed": ["all_users"]}}
            return {"fake": True, **info}
        app_info = _import_attr("yunohost.app", "app_info")
        return {"fake": False, **app_info(app, full=full)}

    def diagnosis_run(self, categories: list[str] | None = None, force: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "categories_run": categories or ["ip", "dnsrecords", "services"]}
        # diagnosis_run() takes an OperationLogger as its first argument and
        # calls .start() on it itself (PHASE0_INVESTIGATION.md) - moulinette's
        # CLI/API dispatch normally constructs this for you, so an in-process
        # caller must replicate that.
        diagnosis_run = _import_attr("yunohost.diagnosis", "diagnosis_run")
        operation_logger_cls = _import_attr("yunohost.log", "OperationLogger")
        operation_logger = operation_logger_cls("diagnosis_run")
        result = diagnosis_run(operation_logger, categories=categories or [], force=force)
        return {"fake": False, **(result or {})}

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

    # -- Phase 5: writes -------------------------------------------------
    #
    # Every write below either returns {"operation_id": ...} (when we
    # construct the OperationLogger ourselves, per PHASE0_INVESTIGATION.md)
    # or omits it (when the underlying function manages its own logger
    # internally, e.g. app_upgrade does one per app) - callers should treat
    # a missing operation_id as "check operations_list() by time/app instead
    # of by id", not as an error.

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
        operation_logger = _new_operation_logger("backup_create")
        try:
            result = backup_create(
                operation_logger,
                name=name,
                description=description,
                apps=apps or [],
                system=system or [],
            )
        except Exception as exc:
            _try_close_with_error(operation_logger, exc)
            raise
        return {"fake": False, "operation_id": operation_logger.name, "result": result}

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
        operation_logger = _new_operation_logger("app_install", related_to=[("app", app)])
        try:
            result = app_install(operation_logger, app, label=label, args=args, force=force)
        except Exception as exc:
            _try_close_with_error(operation_logger, exc)
            raise
        return {"fake": False, "operation_id": operation_logger.name, "result": result}

    def app_upgrade(self, app: str | list[str] | None = None, force: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "app": app, "result": "success"}
        # No operation_logger to construct here: app_upgrade() builds its
        # own internally, once per app it actually upgrades (PHASE0
        # finding), so there's no single id to hand back for a multi-app
        # call - the per-app result dict plus operations_list() cover it.
        app_upgrade = _import_attr("yunohost.app", "app_upgrade")
        result = app_upgrade(app=app or [], force=force)
        return {"fake": False, "app": app, "result": result}

    # -- Phase 6: destructive writes, gated by policy/confirmation -------

    def app_remove(self, app: str, purge: bool = False) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_remove", "app": app, "purged": purge}
        app_remove = _import_attr("yunohost.app", "app_remove")
        operation_logger = _new_operation_logger("app_remove", related_to=[("app", app)])
        try:
            result = app_remove(operation_logger, app, purge=purge)
        except Exception as exc:
            _try_close_with_error(operation_logger, exc)
            raise
        return {"fake": False, "operation_id": operation_logger.name, "app": app, "result": result}

    def backup_restore(
        self,
        name: str,
        apps: list[str] | None = None,
        system: list[str] | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "name": name, "apps": apps or [], "system": system or []}
        # backup_restore() takes no operation_logger - it isn't in the
        # signature (unlike backup_create/app_install/app_remove); see
        # PHASE0-style verification against /tmp/yunohost-src at
        # implementation time. No operation_id to capture here.
        backup_restore = _import_attr("yunohost.backup", "backup_restore")
        result = backup_restore(name, system=system or [], apps=apps or [], force=force)
        return {"fake": False, "name": name, "result": result}

    def system_upgrade(self) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-tools_upgrade", "result": "success"}
        tools_upgrade = _import_attr("yunohost.tools", "tools_upgrade")
        operation_logger = _new_operation_logger("tools_upgrade")
        try:
            result = tools_upgrade(operation_logger, target="system")
        except Exception as exc:
            _try_close_with_error(operation_logger, exc)
            raise
        return {"fake": False, "operation_id": operation_logger.name, "result": result}


def _new_operation_logger(operation: str, **kwargs: Any) -> Any:
    operation_logger_cls = _import_attr("yunohost.log", "OperationLogger")
    return operation_logger_cls(operation, **kwargs)


def _try_close_with_error(operation_logger: Any, exc: Exception) -> None:
    """Best-effort: close the operation log with the error before re-raising.

    Several core functions already do this themselves on handled failure
    paths; this only matters for exceptions they didn't catch. Never lets a
    problem here mask the original exception.
    """
    try:
        operation_logger.error(str(exc))
    except Exception:  # noqa: BLE001 - logging the original failure must not be lost
        pass
