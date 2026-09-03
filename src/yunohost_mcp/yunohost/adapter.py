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
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
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

    def app_resources(self, app: str) -> dict[str, Any]:
        """Return the resource declarations exposed by an app manifest."""
        info = self.app_info(app, full=True)
        manifest = info.get("manifest") or {}
        resources = manifest.get("resources")
        if resources is None:
            resources = info.get("resources", {})
        return {"fake": self.settings.fake_yunohost, "app": app, "resources": resources}

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
        # backup_create()'s own return is {"name": ..., "size": ..., "results": ...}
        # (real archive name, possibly auto-generated if `name` was None) -
        # surfaced at the top level here too so callers (package_run_tests
        # included) get a consistent "name" field regardless of fake/real mode.
        archive_name = result.get("name", name) if isinstance(result, dict) else name
        return {"fake": False, "operation_id": _latest_operation_id(), "name": archive_name, "result": result}

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

    def app_upgrade(
        self, app: str | list[str] | None = None, force: bool = False, file: str | None = None
    ) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "app": app, "file": file, "result": "success"}
        # app_upgrade() is not @is_unit_operation-decorated; it builds its
        # own OperationLogger internally, once per app it actually
        # upgrades, so there's no single id to hand back for a multi-app
        # call - the per-app result dict plus operations_list() cover it.
        # `file` (a local folder or tarball) is what package_upgrade_test
        # uses to upgrade an already-installed app from a candidate source
        # instead of the catalog - app_upgrade() only accepts a single app
        # when file/url is given (PHASE0-style check of the real source).
        app_upgrade = _import_attr("yunohost.app", "app_upgrade")
        result = app_upgrade(app=app or [], force=force, file=file)
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

    def app_change_url(self, app: str, domain: str, path: str) -> dict[str, Any]:
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_change_url", "app": app}
        # @is_unit_operation-decorated (verified against /tmp/yunohost-src
        # directly, per the Errata in PHASE0_INVESTIGATION.md) - no
        # operation_logger passed here either.
        app_change_url = _import_attr("yunohost.app", "app_change_url")
        result = app_change_url(app, domain, path)
        return {"fake": False, "operation_id": _latest_operation_id(), "app": app, "result": result}

    # -- Phase 8: package development -------------------------------------
    #
    # `source` throughout is whatever app_manifest()/app_install() already
    # accept natively - an app id (catalog), a local path, or a git URL
    # (PHASE0's "Name, local path or git URL of the app" from app_install's
    # own docstring) - there is no separate "candidate package" concept to
    # invent here, matching PLAN.md's "do not duplicate YunoHost's own
    # package/resource management where its API already provides it".

    def package_inspect(self, source: str) -> dict[str, Any]:
        """Manifest + declared resources for a candidate package, without
        installing it - app_manifest() already does exactly this (accepts a
        local path or git URL, not just a catalog id), so no separate
        parsing of manifest.toml is needed here."""
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "id": "example",
                "packaging_format": 2,
                "resources": {"system_user": {}, "install_dir": {}, "permissions": {}},
                "unknown_resource_types": [],
            }
        app_manifest = _import_attr("yunohost.app", "app_manifest")
        manifest = app_manifest(source)
        resources = manifest.get("resources", {})
        try:
            known_types = set(_import_attr("yunohost.utils.resources", "AppResourceClassesByType").keys())
            unknown = sorted(set(resources.keys()) - known_types)
        except YunohostUnavailableError:
            unknown = []
        return {"fake": False, **manifest, "unknown_resource_types": unknown}

    def package_lint(self, source: str) -> dict[str, Any]:
        """Run github.com/YunoHost/package_linter against `source` (a local
        path). Separate upstream tool, not part of yunohost core - see
        Settings.package_linter_path. Returns unavailable=True (not fake
        data, not an error) when it isn't configured, since there's no
        in-process equivalent to fall back to."""
        if self.settings.fake_yunohost:
            return {"fake": True, "passed": True, "success": [], "info": [], "warning": [], "error": [], "critical": []}
        if self.settings.package_linter_path is None:
            return {"fake": False, "unavailable": True, "reason": "package_linter_path not configured"}

        import json
        import subprocess

        linter_script = self.settings.package_linter_path / "package_linter.py"
        proc = subprocess.run(
            [self.settings.package_linter_python, str(linter_script), source, "--json"],
            capture_output=True,
            text=True,
            timeout=self.settings.package_linter_timeout_seconds,
            cwd=self.settings.package_linter_path,
        )
        try:
            report = json.loads(proc.stdout)
        except ValueError as exc:
            raise YunohostUnavailableError(
                f"package_linter produced non-JSON output (exit {proc.returncode}): {proc.stderr[-2000:]}"
            ) from exc
        passed = not report.get("error") and not report.get("critical")
        return {"fake": False, "passed": passed, **report}

    # -- Nostr YunoHost catalogue -----------------------------------------

    def catalog_package_inspect(self, source: str, ref: str | None = None) -> dict[str, Any]:
        """Inspect a local or remote package without signing or publishing."""
        self._validate_catalog_source(source, ref)
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "source": source,
                "ref": ref,
                "id": "example",
                "version": "1.0~ynh1",
                "commit": "a" * 40,
                "manifest_hash": "sha256:" + "0" * 64,
                "content_hash": "sha256:" + "1" * 64,
            }
        if ref is not None or source.startswith(("https://", "http://")):
            if not source.startswith("https://"):
                raise ValueError("remote catalogue package sources must use HTTPS")
            args = ["preview"]
            if ref:
                args += ["--ref", ref]
            args.append(source)
            return {"fake": False, **self._run_catalog_json(args)}
        package = self.package_inspect(source)
        return {"fake": False, "source": str(Path(source).resolve()), **package}

    def catalog_publish_plan(self, source: str, ref: str | None = None) -> dict[str, Any]:
        """Build and sign a declaration locally, without contacting relays."""
        self._validate_catalog_source(source, ref)
        relays = self._catalog_relays()
        args = ["publish", "--json", "--dry-run", "--private-key-file", str(self.settings.catalog_publisher_key_path)]
        if relays:
            args += ["--relays", ",".join(relays)]
        if ref is not None:
            args += ["--repository-url", source, "--ref", ref]
        else:
            args += ["--repo", source]
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "source": source,
                "ref": ref,
                "relays": relays,
                "app_id": "example",
                "version": "1.0~ynh1",
                "commit": "a" * 40,
                "manifest_hash": "sha256:" + "0" * 64,
                "content_hash": "sha256:" + "1" * 64,
                "naddr": "naddr1qqxyz",
                "event": {"id": "0" * 64, "kind": 30078},
            }
        result = self._run_catalog_json(args, requires_key=True)
        event = result.get("event", {})
        tags = {tag[0]: tag[1] for tag in event.get("tags", []) if len(tag) >= 2}
        return {
            "fake": False,
            "source": source,
            "ref": ref,
            "relays": relays,
            "app_id": tags.get("d"),
            "version": tags.get("version"),
            "commit": tags.get("commit"),
            "manifest_hash": tags.get("manifest"),
            "content_hash": tags.get("content"),
            **result,
        }

    def catalog_publish(self, source: str, ref: str | None = None) -> dict[str, Any]:
        """Publish a previously planned package declaration to configured relays."""
        self._validate_catalog_source(source, ref)
        relays = self._catalog_relays()
        if not relays:
            raise ValueError("catalog_relays must contain at least one relay URL")
        args = ["publish", "--json", "--private-key-file", str(self.settings.catalog_publisher_key_path), "--relays", ",".join(relays)]
        if ref is not None:
            args += ["--repository-url", source, "--ref", ref]
        else:
            args += ["--repo", source]
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "source": source,
                "ref": ref,
                "relays": [{"relay": r, "published": True} for r in relays],
                "published": True,
                "naddr": "naddr1qqxyz",
                "event": {"id": "0" * 64, "kind": 30078},
                "verification": {"valid": True, "mode": "local-event"},
            }
        result = self._run_catalog_json(args, requires_key=True)
        event = result.get("event")
        if result.get("published") and isinstance(event, dict):
            result["verification"] = self.catalog_verify(json.dumps(event))
        return {"fake": False, **result}

    def catalog_verify(self, event_or_naddr: str) -> dict[str, Any]:
        """Verify a declaration event or fetch and verify an naddr."""
        if self.settings.fake_yunohost:
            return {"fake": True, "valid": True, "value": event_or_naddr}
        if event_or_naddr.startswith("naddr"):
            return {"fake": False, **self._run_catalog_json(["inspect", "--json", event_or_naddr])}
        try:
            event = json.loads(event_or_naddr)
        except json.JSONDecodeError as exc:
            raise ValueError("event_or_naddr must be a JSON event or naddr") from exc
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            json.dump(event, handle)
            event_path = handle.name
        try:
            return {"fake": False, **self._run_catalog_json(["verify", "--json", event_path])}
        finally:
            Path(event_path).unlink(missing_ok=True)

    def _catalog_relays(self) -> list[str]:
        return [relay.strip() for relay in self.settings.catalog_relays.split(",") if relay.strip()]

    def _validate_catalog_source(self, source: str, ref: str | None) -> None:
        if ref is not None:
            if not source.startswith("https://"):
                raise ValueError("a ref may only be used with an HTTPS remote repository")
            if not ref.strip():
                raise ValueError("remote repository ref must not be empty")
            return
        if source.startswith(("https://", "http://")):
            if not source.startswith("https://"):
                raise ValueError("remote catalogue package sources must use HTTPS")
            if self.settings.catalog_require_remote_ref:
                raise ValueError("an explicit ref is required for remote catalogue sources")
            return
        path = Path(source)
        if not path.exists() or not path.is_dir():
            raise ValueError("local catalogue source must be an existing directory")

    def _run_catalog_json(self, args: list[str], *, requires_key: bool = False) -> dict[str, Any]:
        cli = self.settings.catalog_cli_path
        if not cli.is_file() or not os.access(cli, os.X_OK):
            raise YunohostUnavailableError(f"catalog CLI is not executable: {cli}")
        if requires_key:
            key = self.settings.catalog_publisher_key_path
            if not key.is_file() or key.is_symlink():
                raise YunohostUnavailableError(f"catalog publisher key is not a regular file: {key}")
            if key.stat().st_mode & 0o077:
                raise YunohostUnavailableError(f"catalog publisher key is not owner-only (expected mode 0600): {key}")
        try:
            proc = subprocess.run(
                [str(cli), *args],
                capture_output=True,
                text=True,
                timeout=self.settings.catalog_cli_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise YunohostUnavailableError("catalog CLI timed out") from exc
        if len(proc.stdout) > 2_000_000:
            raise YunohostUnavailableError("catalog CLI output exceeded the configured limit")
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise YunohostUnavailableError(
                f"catalog CLI produced invalid JSON (exit {proc.returncode}): {proc.stderr[-2000:]}"
            ) from exc
        if proc.returncode != 0:
            raise YunohostUnavailableError(f"catalog CLI failed (exit {proc.returncode}): {proc.stderr[-2000:]}")
        if not isinstance(result, dict):
            raise YunohostUnavailableError("catalog CLI JSON result must be an object")
        return result

    def package_install_test(self, source: str, label: str | None = None, args: str | None = None) -> dict[str, Any]:
        """app_install() already accepts a local path/git URL as `source` -
        force=True so an experimental/low-quality-flagged candidate package
        doesn't get stuck on the confirmation prompt real install would show
        interactively; that prompt exists for end users installing from the
        catalog, not for a developer iterating on their own package."""
        return self.app_install(source, label=label, args=args, force=True)

    def package_upgrade_test(self, app: str, source: str) -> dict[str, Any]:
        """Upgrade an already-installed `app` from a candidate `source`
        (local path/tarball) instead of the catalog."""
        return self.app_upgrade(app=app, file=source, force=True)

    def package_backup_test(self, app: str) -> dict[str, Any]:
        return self.backup_create(name=f"package-test-{app}", apps=[app])

    def package_restore_test(self, app: str, archive_name: str) -> dict[str, Any]:
        return self.backup_restore(archive_name, apps=[app], force=True)

    def package_change_url_test(self, app: str, domain: str, path: str) -> dict[str, Any]:
        return self.app_change_url(app, domain, path)

    def package_remove_test(self, app: str, purge: bool = True) -> dict[str, Any]:
        return self.app_remove(app, purge=purge)

    def package_run_tests(self, source: str, app_id: str | None = None) -> dict[str, Any]:
        """Run the standard install -> backup -> remove -> restore -> remove
        cycle against `source` in one call (PLAN.md Phase 8's "removes the
        human copy/paste loop"). This is deliberately lighter than
        github.com/YunoHost/package_check's full test matrix (multiple
        Debian versions, LXC isolation, etc.) - that tool exists for CI
        against the whole app catalog; this runs once, directly against the
        live YunoHost this MCP server manages, for a developer's fast local
        iteration loop. Stops at the first failing step (each subsequent
        step depends on the previous one having actually happened) and
        always attempts a final cleanup removal if install succeeded.
        """
        steps: list[dict[str, Any]] = []

        def run_step(step_name: str, fn, *args, **kwargs) -> bool:
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - report the failure, don't crash the whole run
                steps.append({"step": step_name, "passed": False, "error": str(exc)})
                return False
            steps.append({"step": step_name, "passed": True, "result": result})
            return True

        # Determine the app instance id from the manifest *before*
        # installing - app_install()'s own return value doesn't reliably
        # carry it back (real-mode app_install() has no "app" key at all;
        # see its adapter method above), and `source` itself is a path/URL,
        # not the id YunoHost will register the app under.
        installed_app_id = app_id or self.package_inspect(source).get("id") or source
        if isinstance(installed_app_id, list):
            installed_app_id = installed_app_id[0]

        if not run_step("install", self.package_install_test, source):
            return {"fake": self.settings.fake_yunohost, "passed": False, "steps": steps}

        backup_ok = run_step("backup", self.package_backup_test, installed_app_id)
        archive_name = steps[-1]["result"].get("name") if backup_ok else None

        remove_ok = run_step("remove", self.package_remove_test, installed_app_id, True)

        restore_ok = False
        if backup_ok and remove_ok and archive_name:
            restore_ok = run_step("restore", self.package_restore_test, installed_app_id, archive_name)

        # Final cleanup: if restore re-installed the app, remove it again so
        # this doesn't leave test apps behind on the server either way.
        if restore_ok:
            run_step("cleanup_remove", self.package_remove_test, installed_app_id, True)

        passed = all(step["passed"] for step in steps)
        return {"fake": self.settings.fake_yunohost, "passed": passed, "steps": steps}

    # -- Phase 14: high-level composite workflows --------------------------
    #
    # Every method below is built entirely out of the adapter methods
    # above - no new yunohost.* call is introduced here. server.py's tools
    # still run the composites through the same @require_scope /
    # @audited_write / policy-check machinery as the primitives they're
    # built from (PLAN.md: "these workflows should still run through the
    # same policy engine").

    def diagnose_app(self, app: str) -> dict[str, Any]:
        info = self.app_info(app, full=True)
        diagnosis = self.health_check()
        operations = self.operations_list(limit=20)
        related_operations = [
            op
            for op in operations.get("operation", [])
            if app in str(op.get("name", "")) or app in str(op.get("description", ""))
        ]
        return {
            "fake": info.get("fake", False),
            "app": app,
            "app_info": info,
            "diagnosis": diagnosis,
            "related_operations": related_operations,
        }

    def validate_server(self) -> dict[str, Any]:
        server = self.server_info()
        return {
            "fake": server.get("fake", False),
            "server": server,
            "diagnosis": self.health_check(),
            "updates": self.updates_check(),
            "services": self.services_list(),
            "backups": self.backups_list(),
        }

    def test_http_endpoint(self, url: str, timeout_seconds: float = 10.0) -> dict[str, Any]:
        """Reachability probe for safe_upgrade's post-upgrade check. Not a
        yunohost.* call - there's no YunoHost API for "is this URL up" - so
        this makes (or doesn't) a real outbound HTTP request regardless of
        fake_yunohost, *except* that fake_yunohost=True short-circuits it
        entirely: a fake app's fake settings ("domain": "example.com") is a
        real, unrelated domain a test run must never actually contact.
        """
        if self.settings.fake_yunohost:
            return {"fake": True, "url": url, "reachable": True, "status_code": 200, "error": None}

        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, method="GET", headers={"User-Agent": "yunohost-mcp/safe_upgrade"})
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - operator-configured domain, not user input
                return {"fake": False, "url": url, "reachable": True, "status_code": response.status, "error": None}
        except urllib.error.HTTPError as exc:
            # Any HTTP response at all - even 4xx/5xx - means the app is
            # answering requests; only a connection-level failure is "down".
            return {"fake": False, "url": url, "reachable": True, "status_code": exc.code, "error": None}
        except Exception as exc:  # noqa: BLE001 - report as unreachable, don't crash the workflow
            return {"fake": False, "url": url, "reachable": False, "status_code": None, "error": str(exc)}

    def safe_upgrade(self, app: str) -> dict[str, Any]:
        """PLAN.md Phase 14's flagship composite: diagnosis -> app
        inspection -> a fresh safety backup -> upgrade -> post-upgrade
        checks -> a second diagnosis -> one report. Disk-space and
        pre-existing-backup policy checks are the calling tool's job
        (server.py's safe_upgrade wraps this with the same checks
        app_upgrade's own tool uses) - this method focuses on the workflow
        itself. Stops at the first failing step; each later step depends on
        the previous one having actually happened.
        """
        steps: list[dict[str, Any]] = []

        def run_step(step_name: str, fn, *args, **kwargs):
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - report the failure, don't crash the whole workflow
                steps.append({"step": step_name, "passed": False, "error": str(exc)})
                return None
            steps.append({"step": step_name, "passed": True, "result": result})
            return result

        run_step("pre_diagnosis", self.health_check)

        if run_step("inspect_app", self.app_info, app, full=True) is None:
            return {"fake": self.settings.fake_yunohost, "app": app, "passed": False, "steps": steps}

        if (
            run_step(
                "backup",
                self.backup_create,
                name=f"safe-upgrade-{app}",
                description=f"Safety backup before upgrading {app}",
                apps=[app],
            )
            is None
        ):
            return {"fake": self.settings.fake_yunohost, "app": app, "passed": False, "steps": steps}

        if run_step("upgrade", self.app_upgrade, app=app) is None:
            return {"fake": self.settings.fake_yunohost, "app": app, "passed": False, "steps": steps}

        post_info = run_step("check_app", self.app_info, app, full=True)

        url = None
        settings = (post_info or {}).get("settings") or {}
        domain, path = settings.get("domain"), settings.get("path")
        if domain and path is not None:
            url = f"https://{domain}{path}"
            run_step("test_http_endpoint", self.test_http_endpoint, url)

        run_step("post_diagnosis", self.health_check)

        passed = all(step["passed"] for step in steps)
        return {"fake": self.settings.fake_yunohost, "app": app, "passed": passed, "url_tested": url, "steps": steps}

    def repair_app(self, app: str, strategy: str = "conservative") -> dict[str, Any]:
        """Diagnose, then attempt bounded remediation. "conservative" (the
        only strategy implemented) restarts services whose name contains
        this app id, then re-diagnoses - nothing more invasive (no
        reinstall, no upgrade, no forced removal) regardless of findings.
        """
        if strategy != "conservative":
            raise ValueError(f"unknown repair strategy {strategy!r}; only 'conservative' is implemented")

        before = self.diagnose_app(app)
        services = self.services_list().get("services", {})
        matching_services = [name for name in services if app in name]

        if matching_services:
            self.service_restart(matching_services)

        after = self.diagnose_app(app)
        return {
            "fake": before.get("fake", False),
            "app": app,
            "strategy": strategy,
            "restarted_services": matching_services,
            "diagnosis_before": before["diagnosis"],
            "diagnosis_after": after["diagnosis"],
        }


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
