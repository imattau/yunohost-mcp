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
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yunohost_mcp.config import Settings
from yunohost_mcp.redaction import redact_text


class YunohostUnavailableError(RuntimeError):
    """Raised when a real YunoHost call is attempted but yunohost.* can't be imported."""


class NoAppsToUpgradeError(YunohostUnavailableError, ValueError):
    """The requested app upgrade has no available upgrade."""


class ToolInputError(ValueError):
    """Deliberate caller-input validation failures raised by this adapter
    (a bad catalog source URL, a missing required ref, an unknown repair
    strategy, ...) - a caller/model could react to the message and retry
    with different arguments, unlike a plain ValueError raised
    accidentally somewhere unrelated (which should keep crashing loudly
    with a traceback, not look identical to a deliberate validation
    error). See policy/enforcement.py's translate_known_errors, which
    catches this specific type (not bare ValueError) for exactly that
    reason."""


_yunohost_runtime_initialized = False


class _HeadlessInterface:
    """Stand-in for a real moulinette Interface (Cli/Api).

    Only `.type` is used by yunohost.* outside of an actual request/response
    cycle (e.g. diagnosis.py's m18n_ formatter branches on
    `Moulinette.interface.type` to decide whether to strip CLI-oriented HTML
    tags from messages) - "api" keeps that HTML intact, which is more useful
    to an MCP client than CLI-stripped text.
    """

    type = "api"


def _ensure_yunohost_runtime_initialized() -> None:
    """Initialize moulinette/yunohost process-global state before any real
    yunohost.* call.

    Several yunohost.* modules reach into state that's normally set up by
    moulinette.cli()/moulinette.api() (or yunohost.init(), which wraps
    them) - the CLI/API bootstrap this adapter deliberately bypasses by
    importing yunohost.* directly in-process (see module docstring).
    Skipping each raises, the first time a call happens to touch it:
      - m18n.translator unset (needed by e.g. yunohost.service):
        AttributeError: 'Moulinette18n' object has no attribute 'translator'
      - Moulinette.interface unset (needed by yunohost.diagnosis's message
        formatting):
        AttributeError: 'NoneType' object has no attribute 'type'
      - the custom SUCCESS log level/Logger class unset (needed by e.g.
        yunohost.service.service_restart's success-path logging):
        AttributeError: 'Logger' object has no attribute 'success'
    yunohost.init_i18n() is yunohost's own documented hook for the m18n
    case, for exactly this "in-process, not via moulinette.cli" scenario.
    There's no equivalent upstream hook for the other two, so they're
    reproduced directly here from yunohost.utils.logging.init_logging()'s
    relevant lines - deliberately *not* calling init_logging() itself,
    since its dictConfig(..., disable_existing_loggers=True) would
    reconfigure/silence this server's own loggers (uvicorn's included) as
    a side effect.
    """
    global _yunohost_runtime_initialized
    if _yunohost_runtime_initialized:
        return
    _yunohost_runtime_initialized = True
    # Each import/init below is independent - and best-effort via ImportError
    # - so a missing `moulinette` package (or a `yunohost` one) doesn't skip
    # the others, and none of them block the caller's own import of the
    # target module/attr, which raises YunohostUnavailableError if it's the
    # real one that's actually missing (e.g. adapter tests inject fake
    # yunohost.* submodules straight into sys.modules without a real
    # top-level yunohost/moulinette package).
    try:
        from yunohost import init_i18n
    except ImportError:
        pass
    else:
        init_i18n()
    try:
        from logging import addLevelName, setLoggerClass

        from yunohost.utils.logging import SUCCESS, YunohostLogger
    except ImportError:
        pass
    else:
        addLevelName(SUCCESS, "SUCCESS")
        setLoggerClass(YunohostLogger)
    try:
        from moulinette import Moulinette
    except ImportError:
        return
    if Moulinette.interface is None:
        Moulinette._interface = _HeadlessInterface()


def _import_attr(module_name: str, attr: str) -> Any:
    try:
        _ensure_yunohost_runtime_initialized()
        module = importlib.import_module(module_name)
        return getattr(module, attr)
    except ImportError as exc:
        raise YunohostUnavailableError(
            f"{module_name} is not importable on this host; "
            "set YUNOHOST_MCP_FAKE_YUNOHOST=true for local development"
        ) from exc


_SYSTEM_PYTHON_CALL_SCRIPT = """
import importlib
import json
import sys

module_name, attr = {module_name!r}, {attr!r}

try:
    import yunohost

    yunohost.init_i18n()
except ImportError:
    pass
try:
    from logging import addLevelName, setLoggerClass

    from yunohost.utils.logging import SUCCESS, YunohostLogger

    addLevelName(SUCCESS, "SUCCESS")
    setLoggerClass(YunohostLogger)
except ImportError:
    pass
try:
    from moulinette import Moulinette

    class _HeadlessInterface:
        type = "api"

    if Moulinette.interface is None:
        Moulinette._interface = _HeadlessInterface()
except ImportError:
    pass

fn = getattr(importlib.import_module(module_name), attr)
kwargs = json.loads(sys.stdin.read())
result = fn(**kwargs)
json.dump(result, sys.stdout, default=str)
"""


def _call_via_system_python(module_name: str, attr: str, kwargs: dict[str, Any], settings: Settings) -> Any:
    """Call a real yunohost.* function in a subprocess using the *system*
    python3 rather than importing it in-process.

    Needed specifically for calls that transitively import
    yunohost.utils.form (e.g. backup's storage-location settings) - that
    module defines pydantic models using pydantic v1's
    @validator(field=..., config=...) signature, which only works against
    the actual pydantic v1 the system's python3 has on its path (Debian's
    apt-installed python3-pydantic). This venv installs its own newer
    pydantic v2 (required by the mcp SDK and this server's own models),
    which shadows the system one for any in-process import - and once
    loaded, every subsequent `import pydantic` anywhere in this process
    returns that same cached v2 module, so there is no way to get v1's
    behavior in-process once v2 has already been imported once. A
    subprocess using an interpreter that never sees this venv's
    site-packages at all sidesteps the conflict entirely.

    kwargs must be JSON-serializable; the target function's return value
    must be too (or json.dump(..., default=str)-representable).
    """
    script = _SYSTEM_PYTHON_CALL_SCRIPT.format(module_name=module_name, attr=attr)
    proc = subprocess.run(
        [settings.system_python, "-c", script],
        input=json.dumps(kwargs),
        capture_output=True,
        text=True,
        timeout=settings.system_python_timeout_seconds,
    )
    if proc.returncode != 0:
        raise YunohostUnavailableError(
            f"{module_name}.{attr} failed in the system-python subprocess "
            f"(exit {proc.returncode}): {proc.stderr[-4000:]}"
        )
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise YunohostUnavailableError(
            f"{module_name}.{attr} produced non-JSON output from the system-python "
            f"subprocess: {proc.stdout[-2000:]}"
        ) from exc


@dataclass
class YunohostAdapter:
    """Thin wrapper around yunohost.* read operations."""

    settings: Settings

    _BROKERED_METHODS = frozenset(
        {
            "server_info",
            "health_check",
            "diagnosis_run",
            "catalog_package_inspect",
            "catalog_verify",
            "catalog_list",
            "catalog_publish_plan",
            "catalog_publish",
            "package_inspect",
            "package_lint",
            "package_run_tests",
            "package_install_test",
            "package_upgrade_test",
            "package_backup_test",
            "package_restore_test",
            "package_change_url_test",
            "package_remove_test",
            "safe_upgrade",
            "repair_app",
            "apps_list",
            "app_info",
            "app_resources",
            "app_config_get",
            "app_install",
            "app_upgrade",
            "app_remove",
            "app_change_url",
            "app_config_set",
            "backup_restore",
            "system_upgrade",
            "migrations_run",
            "firewall_open",
            "firewall_close",
            "firewall_reload",
            "user_create",
            "user_update",
            "user_delete",
            "user_group_create",
            "user_group_update",
            "user_group_delete",
            "user_permission_add",
            "user_permission_remove",
            "domain_add",
            "domain_cert_install",
            "diagnosis_get",
            "plan_app_upgrade",
            "diagnose_app",
            "validate_server",
            "domain_cert_info",
            "services_list",
            "service_status",
            "service_logs",
            "service_restart",
            "domains_list",
            "users_list",
            "backups_list",
            "backup_create",
            "backup_created_at_times",
            "free_space_bytes",
            "user_group_list",
            "user_permission_list",
            "operations_list",
            "operation_status",
            "operation_logs",
            "updates_check",
            "updates_refresh",
            "migrations_list",
            "migrations_state",
            "firewall_list",
            "firewall_is_open",
        }
    )

    def __post_init__(self) -> None:
        """Prevent accidental in-process privilege fallback in broker mode.

        Until every adapter capability has a typed broker operation, an
        unprivileged frontend must fail clearly instead of trying the old
        direct YunoHost path. The root helper constructs its adapter with
        broker mode disabled, so registered operations remain executable.
        """
        if self.settings.broker_socket_path is None:
            return
        for name in dir(self):
            if name.startswith("_") or not callable(getattr(self, name, None)):
                continue
            if name in self._BROKERED_METHODS:
                continue
            def guarded(*args, _name=name, **kwargs):
                raise YunohostUnavailableError(
                    f"adapter operation {_name!r} is not yet available through the privileged broker"
                )

            object.__setattr__(self, name, guarded)

    def _broker_call(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Use the local broker when configured; otherwise return ``None``.

        This keeps fake mode and local stdio development unchanged while
        giving the packaged HTTP frontend an explicit migration switch.
        """
        if self.settings.broker_socket_path is None:
            return None
        from yunohost_mcp.broker.client import call

        return call(
            operation,
            arguments,
            socket_path=self.settings.broker_socket_path,
            timeout=self.settings.request_timeout_seconds,
        )

    def server_info(self) -> dict[str, Any]:
        brokered = self._broker_call("server.info", {})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("health.check", {})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("apps.list", {"full": full})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            app = {"id": "nextcloud", "name": "Nextcloud", "version": "28.0.1~ynh1"}
            if full:
                app["description"] = "Self-hosted productivity platform"
            return {"fake": True, "apps": [app]}
        app_list = _import_attr("yunohost.app", "app_list")
        return {"fake": False, **app_list(full=full)}

    def app_info(self, app: str, full: bool = False) -> dict[str, Any]:
        brokered = self._broker_call("app.info", {"app": app, "full": full})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("app.resources", {"app": app})
        if brokered is not None:
            return brokered
        info = self.app_info(app, full=True)
        manifest = info.get("manifest") or {}
        resources = manifest.get("resources")
        if resources is None:
            resources = info.get("resources", {})
        return {"fake": self.settings.fake_yunohost, "app": app, "resources": resources}

    def app_config_get(self, app: str, key: str = "", full: bool = False, export: bool = False) -> dict[str, Any]:
        """Read an app's config-panel-defined settings (yunohost.app.app_config_get).

        `key` is a dotted "<panel>.<section>.<option>" id, or "" for the
        whole panel. `full` returns the panel's schema (labels, types,
        current values) - what a caller should inspect before calling
        app_config_set with an unfamiliar `key`; `export` returns a flat
        key/value mapping instead. An app with no config_panel.toml
        returns an empty config, not an error (matches the real API's own
        "be permissive when no config panel found" behavior).
        """
        brokered = self._broker_call("app.config_get", {"app": app, "key": key, "full": full, "export": export})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "app": app, "key": key, "config": {}}
        # app_config_get transitively imports utils/configpanel.py, which
        # (like utils/form.py - see _call_via_system_python's docstring)
        # defines pydantic v1-style @validator models - same conflict as
        # app_install/domain_add/app_change_url.
        result = _call_via_system_python(
            "yunohost.app", "app_config_get", {"app": app, "key": key, "full": full, "export": export}, self.settings
        )
        return {"fake": False, "app": app, "key": key, "config": result}

    def app_config_set(
        self, app: str, key: str, value: str, confirmation_id: str | None = None
    ) -> dict[str, Any]:
        """Apply one app config-panel setting (yunohost.app.app_config_set).

        `key` must be the full dotted "<panel>.<section>.<option>" id
        from app_config_get(app, full=True) - not a bare option name the
        panel happens to display, since a panel can reuse the same option
        id across different sections. Setting one key at a time (rather
        than the CLI's bulk `args="k1=v1&k2=v2"` form) keeps each write
        traceable to exactly one confirmation/audit entry.
        """
        brokered = self._broker_call(
            "app.config_set", {"app": app, "key": key, "value": value, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_config_set", "app": app, "key": key, "value": value}
        # Same pydantic v1/v2 conflict as app_config_get - see there.
        _call_via_system_python(
            "yunohost.app", "app_config_set", {"app": app, "key": key, "value": value}, self.settings
        )
        return {"fake": False, "operation_id": _latest_operation_id(), "app": app, "key": key, "value": value}

    def diagnosis_run(self, categories: list[str] | None = None, force: bool = False) -> dict[str, Any]:
        brokered = self._broker_call("diagnosis.run", {"categories": categories, "force": force})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("services.status", {"names": []})
        if brokered is not None:
            return {"services": brokered.get("services", brokered)}
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

    def service_logs(
        self,
        service: str,
        *,
        since: str | None = None,
        until: str | None = None,
        priority: str | None = None,
        grep: str | None = None,
        lines: int = 200,
    ) -> dict[str, Any]:
        """Structured systemd journal entries for one YunoHost-managed
        service - normalized timestamp/service/priority/message per
        entry, filterable by time range (`since`/`until`, journalctl's
        own syntax: "-1h", "2026-09-03 07:00:00", "today", ...), syslog
        `priority` (emerg/alert/crit/err/warning/notice/info/debug, or a
        range like "err..emerg"), and a `grep` text pattern.

        Fills a real gap: operation_logs()/package_logs() only cover
        formal YunoHost *operations* (backups, installs, ...) - never a
        service's own crash/error output on its way to becoming one.
        Every real bug found against a live YunoHost host during this
        project's own development needed exactly this, previously
        obtainable only by reading `journalctl -u <service>` over SSH one
        call at a time.

        `service` must be one of services_list()'s own known service
        names - deliberately not "any systemd unit at all", so this
        can't be used to read some unrelated system service's journal
        (which might carry content this MCP server has no business
        exposing) just because the caller happens to guess its unit
        name.
        """
        brokered = self._broker_call(
            "service.logs",
            {"service": service, "since": since, "until": until, "priority": priority, "grep": grep, "lines": lines},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "service": service,
                "entries": [
                    {
                        "timestamp": "2026-09-03T12:00:00+00:00",
                        "service": service,
                        "priority": "info",
                        "message": f"fake log entry for {service}",
                    }
                ],
            }
        known_services = set(self.services_list().get("services", {}))
        if service not in known_services:
            raise ToolInputError(f"{service!r} is not a known YunoHost-managed service")

        capped_lines = max(1, min(lines, self.settings.service_logs_max_lines))
        args = [
            self.settings.journalctl_path,
            "-u",
            service,
            "--no-pager",
            "-o",
            "json",
            "-n",
            str(capped_lines),
        ]
        if since:
            args += ["--since", since]
        if until:
            args += ["--until", until]
        if priority:
            args += ["-p", priority]
        if grep:
            args += ["--grep", grep]

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.settings.service_logs_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise YunohostUnavailableError("journalctl timed out") from exc
        if proc.returncode != 0:
            raise YunohostUnavailableError(f"journalctl failed (exit {proc.returncode}): {proc.stderr[-2000:]}")

        entries = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.append(_normalize_journal_entry(raw, default_service=service))
        return {"fake": False, "service": service, "entries": entries}

    def service_status(self, names: list[str]) -> dict[str, Any]:
        brokered = self._broker_call("services.status", {"names": names})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "services": {name: {"status": "running"} for name in names}}
        service_status = _import_attr("yunohost.service", "service_status")
        return {"fake": False, "services": service_status(names)}

    def domains_list(self) -> dict[str, Any]:
        brokered = self._broker_call("domains.list", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "domains": ["example.com"], "main": "example.com"}
        domain_list = _import_attr("yunohost.domain", "domain_list")
        return {"fake": False, **domain_list()}

    def users_list(self) -> dict[str, Any]:
        brokered = self._broker_call("users.list", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "users": {"alice": {"fullname": "Alice Example", "mail": "alice@example.com"}}}
        # Keep this in the system interpreter like the other LDAP-backed
        # YunoHost calls. The MCP venv does not reliably carry YunoHost's
        # full runtime/LDAP dependency set, and an import/runtime failure in
        # the root helper otherwise becomes the unhelpful "internal broker
        # error" at the MCP boundary.
        return {"fake": False, **_call_via_system_python("yunohost.user", "user_list", {}, self.settings)}

    # user_create/user_delete/user_update/user_group_create/user_group_delete/
    # user_group_update are @is_unit_operation-decorated (yunohost.user), same
    # no-manual-operation_logger convention as app_remove/domain_add above -
    # called with real args only, letting the decorator prepend its own
    # OperationLogger. None of them import yunohost.utils.form (checked
    # against /tmp/yunohost-src at review time: neither user.py nor
    # permission.py references it), so - unlike domain_add/app_install -
    # there's no pydantic v1/v2 conflict requiring _call_via_system_python
    # here; a plain in-process _import_attr call is fine.
    def user_create(
        self,
        username: str,
        domain: str,
        password: str,
        fullname: str,
        mailbox_quota: str | None = "0",
        admin: bool = False,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "user.create",
            {"username": username, "domain": domain, "password": password, "fullname": fullname, "mailbox_quota": mailbox_quota, "admin": admin, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-user_create", "username": username}
        user_create = _import_attr("yunohost.user", "user_create")
        result = user_create(
            username=username,
            domain=domain,
            password=password,
            fullname=fullname,
            mailbox_quota=mailbox_quota,
            admin=admin,
        )
        return {"fake": False, "operation_id": _latest_operation_id(), "username": username, "result": result}

    def user_update(
        self,
        username: str,
        mail: str | None = None,
        change_password: str | None = None,
        add_mailforward: list[str] | None = None,
        remove_mailforward: list[str] | None = None,
        add_mailalias: list[str] | None = None,
        remove_mailalias: list[str] | None = None,
        mailbox_quota: str | None = None,
        fullname: str | None = None,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "user.update",
            {"username": username, "mail": mail, "change_password": change_password, "add_mailforward": add_mailforward, "remove_mailforward": remove_mailforward, "add_mailalias": add_mailalias, "remove_mailalias": remove_mailalias, "mailbox_quota": mailbox_quota, "fullname": fullname, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-user_update", "username": username}
        user_update = _import_attr("yunohost.user", "user_update")
        result = user_update(
            username=username,
            mail=mail,
            change_password=change_password,
            add_mailforward=add_mailforward,
            remove_mailforward=remove_mailforward,
            add_mailalias=add_mailalias,
            remove_mailalias=remove_mailalias,
            mailbox_quota=mailbox_quota,
            fullname=fullname,
        )
        return {"fake": False, "operation_id": _latest_operation_id(), "username": username, "result": result}

    def user_delete(self, username: str, purge: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call(
            "user.delete", {"username": username, "purge": purge, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-user_delete", "username": username}
        user_delete = _import_attr("yunohost.user", "user_delete")
        user_delete(username=username, purge=purge)
        return {"fake": False, "operation_id": _latest_operation_id(), "username": username}

    def user_group_list(self) -> dict[str, Any]:
        brokered = self._broker_call("user.groups", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "groups": {"all_users": {"members": ["alice"]}}}
        return {
            "fake": False,
            **_call_via_system_python("yunohost.user", "user_group_list", {}, self.settings),
        }

    def user_group_create(self, groupname: str, confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call("user.group_create", {"groupname": groupname, "confirmation_id": confirmation_id})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-user_group_create", "groupname": groupname}
        user_group_create = _import_attr("yunohost.user", "user_group_create")
        result = user_group_create(groupname=groupname)
        return {"fake": False, "operation_id": _latest_operation_id(), "groupname": groupname, "result": result}

    def user_group_update(
        self, groupname: str, add: list[str] | None = None, remove: list[str] | None = None,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "user.group_update", {"groupname": groupname, "add": add, "remove": remove, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-user_group_update", "groupname": groupname}
        user_group_update = _import_attr("yunohost.user", "user_group_update")
        result = user_group_update(groupname=groupname, add=add, remove=remove)
        return {"fake": False, "operation_id": _latest_operation_id(), "groupname": groupname, "result": result}

    def user_group_delete(self, groupname: str, confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call("user.group_delete", {"groupname": groupname, "confirmation_id": confirmation_id})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-user_group_delete", "groupname": groupname}
        user_group_delete = _import_attr("yunohost.user", "user_group_delete")
        user_group_delete(groupname=groupname)
        return {"fake": False, "operation_id": _latest_operation_id(), "groupname": groupname}

    def user_permission_list(self) -> dict[str, Any]:
        brokered = self._broker_call("user.permissions", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "permissions": {"myapp.main": {"allowed": ["all_users"]}}}
        return {
            "fake": False,
            **_call_via_system_python("yunohost.user", "user_permission_list", {"full": True}, self.settings),
        }

    # user_permission_add/user_permission_remove are @is_flash_unit_operation
    # (flash=True) - log.py's is_unit_operation() only prepends an
    # OperationLogger positionally when flash=False, so unlike every other
    # write in this file these two never take one at all; nothing to avoid
    # corrupting here, no _latest_operation_id() to recover either (a flash
    # operation's log entry isn't findable the same way - PLAN.md's
    # operation_status/operation_logs tools won't have an id for this call).
    def user_permission_add(self, permission: str, names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call(
            "user.permission_add", {"permission": permission, "names": names, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "permission": permission, "names": names}
        user_permission_add = _import_attr("yunohost.user", "user_permission_add")
        result = user_permission_add(permission=permission, names=names)
        return {"fake": False, "permission": permission, "result": result}

    def user_permission_remove(self, permission: str, names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call(
            "user.permission_remove", {"permission": permission, "names": names, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "permission": permission, "names": names}
        user_permission_remove = _import_attr("yunohost.user", "user_permission_remove")
        result = user_permission_remove(permission=permission, names=names)
        return {"fake": False, "permission": permission, "result": result}

    def backups_list(self) -> dict[str, Any]:
        brokered = self._broker_call("backups.list", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "archives": ["20260901-000000"]}
        backup_list = _import_attr("yunohost.backup", "backup_list")
        return {"fake": False, **backup_list()}

    def backup_created_at_times(self) -> dict[str, float]:
        """Real per-archive creation time (unix timestamp), keyed by
        archive name - for policy/rules.py's check_recent_backup.

        Deliberately NOT derived from the archive *name*: only an
        unnamed backup_create() call produces a YYYYMMDD-HHMMSS name
        (yunohost.backup.BackupManager._define_backup_name()) - a custom
        `name` (this adapter's own backup_create() accepts one) doesn't,
        and critically, neither does yunohost's own automatic pre-upgrade
        safety backup, always named "<app>-pre-upgrade1"/
        "<app>-pre-upgrade2" (see yunohost/app.py's app_upgrade()) -
        making name-based date parsing unable to recognize the single
        most common kind of "recent backup" this check exists to verify.
        backup_list(with_info=True)'s "created_at" (read from each
        archive's info.json, independent of naming) is correct instead.
        """
        brokered = self._broker_call("backups.created_at", {})
        if brokered is not None:
            return brokered.get("created_at", {})
        import datetime as _dt

        if self.settings.fake_yunohost:
            return {"20260901-000000": _dt.datetime(2026, 9, 1, tzinfo=_dt.timezone.utc).timestamp()}
        backup_list = _import_attr("yunohost.backup", "backup_list")
        archives = backup_list(with_info=True).get("archives", {})
        return {
            name: meta["created_at"].replace(tzinfo=_dt.timezone.utc).timestamp()
            for name, meta in archives.items()
            if isinstance(meta, dict) and "created_at" in meta
        }

    def free_space_bytes(self, path: str = "/") -> int:
        """Real bytes free at `path`, for policy/rules.py's check_free_space.

        Fake-aware like every other real-world read in this adapter:
        fake_yunohost=True reports a large canned figure instead of
        touching the real filesystem. Without this, check_free_space
        previously called shutil.disk_usage() directly and unconditionally
        - the one policy check in the codebase that ignored fake_yunohost
        entirely, so a "validate_server"/health_check() call correctly
        reporting a fake, always-healthy diagnosis could still be followed
        by app_upgrade's free-space check failing for real, against
        whatever machine happens to be running this process (e.g. a
        disk-constrained CI runner or dev container) - a discrepancy
        indistinguishable from a genuine low-disk condition on the actual
        YunoHost server. Real (non-fake) mode is unaffected: this still
        calls the real shutil.disk_usage(path).free.
        """
        brokered = self._broker_call("system.free_space", {"path": path})
        if brokered is not None:
            return int(brokered["free_bytes"])
        if self.settings.fake_yunohost:
            return 100 * 1000**3
        return shutil.disk_usage(path).free

    def operations_list(self, limit: int | None = None) -> dict[str, Any]:
        brokered = self._broker_call("operations.list", {"limit": limit})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("operation.status", {"name": name})
        if brokered is not None:
            return brokered
        # log_show() is also what backs operation_logs(); this method
        # exists as its own scope-checked MCP tool per PLAN.md's v0.1 list
        # ("operation_status" vs "operation_logs"), both reading the same
        # underlying record.
        return self.operation_logs(name)

    def operation_logs(self, name: str, tail_lines: int | None = None) -> dict[str, Any]:
        brokered = self._broker_call("operation.logs", {"name": name, "tail_lines": tail_lines})
        if brokered is not None:
            return brokered
        """`tail_lines` caps how many of the most recent log lines are
        returned - defaults to Settings.operation_logs_default_tail_lines
        (a real install/upgrade log can run to thousands of lines of raw
        shell trace output; callers that genuinely need the full log can
        still ask via a larger tail_lines). Regardless of size, `number`
        is always passed through explicitly to log_show() - never
        omitted - because of a real bug in yunohost.log.log_show() itself:
        called with no `number` at all, it takes a different internal
        branch (`read_file()` returning the whole log as one string) than
        when a number is given (`_tail()`, returning a real list of
        lines), then unconditionally does `list(logs)` on whichever it
        got - exploding the no-number case's plain string into a list of
        *individual characters* instead of lines.

        Each returned line also passes through redact_text() - a shell
        trace routinely contains KEY=VALUE-shaped secrets (an app's own
        install/upgrade script setting a password, an API token in an
        env var, ...) that redact_response's key-based redaction can
        never reach, since the *line*'s own "key" is just "logs", not
        anything sensitive-sounding.
        """
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "name": name,
                "success": True,
                "started_at": "2026-09-01T12:00:00",
                "log": "fake log content for " + name,
            }
        log_show = _import_attr("yunohost.log", "log_show")
        effective_tail = tail_lines if tail_lines is not None else self.settings.operation_logs_default_tail_lines
        result = log_show(name, number=effective_tail)
        logs = result.get("logs")
        if isinstance(logs, list):
            result = {**result, "logs": [redact_text(line) if isinstance(line, str) else line for line in logs]}
        return {"fake": False, **result}

    def updates_check(self) -> dict[str, Any]:
        # Deliberately the no-refresh, cache-only variant: a real network
        # catalog refresh (tools_update()) mutates on-disk cache state and
        # belongs with Phase 5's write tools, not v0.1's read-only scope.
        brokered = self._broker_call("updates.check", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "apps": [{"id": "nextcloud", "current_version": "28.0.1~ynh1", "new_version": "28.0.2~ynh1"}],
                "system": [],
            }
        tools_update_norefresh = _import_attr("yunohost.tools", "tools_update_norefresh")
        return {"fake": False, **tools_update_norefresh()}

    _UPDATES_REFRESH_TARGETS = frozenset({"system", "apps", "all"})

    def updates_refresh(self, target: str = "apps") -> dict[str, Any]:
        """The real, network-refreshing counterpart to updates_check() -
        `apt-get update` and/or a re-fetch of every registered app catalog
        source (including nostr_catalog's local /v3/apps.json feed), then
        re-reads what's now upgradable. Deliberately deferred out of
        updates_check() itself in Phase 4 (see its comment) since it
        mutates on-disk cache state; this is that write, added once there
        was an actual caller for it (confirming a freshly `catalog_publish`-
        ed package shows up in the live catalog).

        Not gated behind a write-scope/confirmation like apps.install etc:
        it only refreshes cached metadata, doesn't touch installed apps,
        and yunohost.tools.tools_update() is @is_unit_operation-decorated
        the same way diagnosis_run's underlying call is - see this class's
        Phase 5/6 comment on why no operation_logger is passed here.
        """
        brokered = self._broker_call("updates.refresh", {"target": target})
        if brokered is not None:
            return brokered
        if target not in self._UPDATES_REFRESH_TARGETS:
            raise ToolInputError(f"target must be one of {sorted(self._UPDATES_REFRESH_TARGETS)}, got {target!r}")
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "target": target,
                "apps": [{"id": "nextcloud", "current_version": "28.0.1~ynh1", "new_version": "28.0.2~ynh1"}],
                "system": [],
            }
        tools_update = _import_attr("yunohost.tools", "tools_update")
        result = tools_update(target=target)
        return {"fake": False, "target": target, **result}

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

    def domain_add(
        self, domain: str, install_letsencrypt_cert: bool = False, confirmation_id: str | None = None
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "domain.add",
            {"domain": domain, "install_letsencrypt_cert": install_letsencrypt_cert, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "operation_id": "20260903-000000-domain_add",
                "domain": domain,
                "certificate": {"CA_type": "letsencrypt" if install_letsencrypt_cert else "selfsigned"},
            }
        # @is_unit_operation-decorated (yunohost.domain), same
        # no-manual-operation_logger convention as service_restart et al
        # just below. ignore_dyndns=True is deliberate and not exposed as
        # a parameter: without it, a bare *.nohost.me/*.noho.st/*.ynh.fr
        # *top-level* domain name (e.g. "newname.nohost.me", not a
        # subdomain of one already registered) triggers a real DynDNS
        # account subscription - and domain_add()'s ToS-acknowledgement
        # prompt only fires when Moulinette.interface.type == "cli" and
        # the process has a tty, neither true here, so that consent step
        # would be silently skipped entirely rather than raising. Always
        # treating the name as a plain custom domain avoids that; a
        # subdomain of an already-registered DynDNS domain (the normal
        # case - e.g. new-app.example.nohost.me under an existing
        # example.nohost.me) is unaffected either way.
        #
        # domain_add() transitively imports yunohost.utils.form (domain
        # registration re-parses the same DomainOption/GroupOption machinery
        # app_install does) - same pydantic v1/v2 conflict as app_install/
        # backup_create/package_inspect, see _call_via_system_python's
        # docstring. Must go through the system-python subprocess too.
        _call_via_system_python(
            "yunohost.domain",
            "domain_add",
            {"domain": domain, "ignore_dyndns": True, "install_letsencrypt_cert": install_letsencrypt_cert},
            self.settings,
        )
        certificate_status = _import_attr("yunohost.certificate", "certificate_status")
        certificate = certificate_status([domain]).get("certificates", {}).get(domain, {})
        return {
            "fake": False,
            "operation_id": _latest_operation_id(),
            "domain": domain,
            "certificate": certificate,
        }

    def domain_cert_info(self, domain: str) -> dict[str, Any]:
        """Read-only certificate status for an already-registered domain
        (yunohost.certificate.certificate_status, full=True): CA type/name,
        remaining validity in days, a style/summary badge, and (full-only)
        ACME_eligible/has_wildcards. Does not import yunohost.utils.form,
        so - unlike domain_add - no pydantic v1/v2 conflict; a plain
        in-process _import_attr call is fine.
        """
        brokered = self._broker_call("domain.certificate_info", {"domain": domain})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "domain": domain,
                "certificate": {
                    "CA_name": "Fake CA",
                    "CA_type": "selfsigned",
                    "validity": 3650,
                    "style": "warning",
                    "summary": "selfsigned",
                    "ACME_eligible": True,
                    "has_wildcards": False,
                },
            }
        certificate_status = _import_attr("yunohost.certificate", "certificate_status")
        certificate = certificate_status([domain], full=True).get("certificates", {}).get(domain, {})
        return {"fake": False, "domain": domain, "certificate": certificate}

    def domain_cert_install(
        self, domain: str, letsencrypt: bool = True, staging: bool = False, confirmation_id: str | None = None
    ) -> dict[str, Any]:
        """Issue/renew a certificate for an *existing* domain in place
        (yunohost.certificate.certificate_install) rather than the
        remove-and-recreate-the-domain workaround - force=True so this
        works whether the domain currently has a selfsigned or an existing
        letsencrypt cert (certificate_install's own default refuses to
        replace a non-selfsigned cert without force).

        `staging` has no effect: this YunoHost version's certmanager only
        knows the production ACME endpoint (no LE staging CA wired in), so
        staging=True is rejected outright rather than silently issuing a
        production cert - staying explicit here is exactly why the tool
        requires it to be passed rather than defaulting True.

        On ACME failure, certificate_install() raises after attempting
        every domain; that's caught here and reported back as
        `acme_error` alongside the resulting (possibly still-selfsigned)
        certificate status, rather than surfacing as an opaque tool
        crash.
        """
        brokered = self._broker_call(
            "domain.cert_install",
            {"domain": domain, "letsencrypt": letsencrypt, "staging": staging, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if staging:
            raise ToolInputError(
                "staging ACME issuance is not supported by this YunoHost version "
                "(certmanager only has the production Let's Encrypt endpoint configured); "
                "call with staging=False"
            )
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "operation_id": "20260903-000000-domain_cert_install",
                "domain": domain,
                "requested": "letsencrypt" if letsencrypt else "selfsigned",
                "acme_error": None,
                "certificate": {"CA_type": "letsencrypt" if letsencrypt else "selfsigned"},
            }
        certificate_install = _import_attr("yunohost.certificate", "certificate_install")
        YunohostError = _import_attr("yunohost.utils.error", "YunohostError")
        acme_error: str | None = None
        try:
            certificate_install([domain], force=True, self_signed=not letsencrypt)
        except YunohostError as exc:
            acme_error = str(exc)
        certificate_status = _import_attr("yunohost.certificate", "certificate_status")
        certificate = certificate_status([domain], full=True).get("certificates", {}).get(domain, {})
        return {
            "fake": False,
            "operation_id": _latest_operation_id(),
            "domain": domain,
            "requested": "letsencrypt" if letsencrypt else "selfsigned",
            "acme_error": acme_error,
            "certificate": certificate,
        }

    def service_restart(self, names: list[str], confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call("service.restart", {"names": names, "confirmation_id": confirmation_id})
        if brokered is not None:
            return brokered
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
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "backup.create",
            {
                "name": name,
                "description": description,
                "apps": apps,
                "system": system,
                "confirmation_id": confirmation_id,
            },
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "operation_id": "20260903-000000-backup_create",
                "name": name or "fake-backup",
            }
        result = _call_via_system_python(
            "yunohost.backup",
            "backup_create",
            {"name": name, "description": description, "apps": apps or [], "system": system or []},
            self.settings,
        )
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
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "app.install",
            {"app": app, "label": label, "args": args, "force": force, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_install", "app": app}
        # app_install() re-parses the target manifest's [install] options
        # (ask_questions_and_parse_answers -> parse_raw_options ->
        # OptionsModel) every call, which for any app with a `type =
        # "domain"`/`"group"` question hits DomainOption/GroupOption's
        # pydantic v1-style @validator("choices", pre=True, always=True)
        # (yunohost.utils.form again - same conflict as backup_create/
        # backup_restore/package_inspect, see _call_via_system_python's
        # docstring). In-process, that validator silently never runs
        # under this venv's pydantic v2, so `choices` - meant to be
        # auto-populated from domain_list()/user_group_list() - looks
        # like a plain missing required field instead: "While parsing
        # manifest: ... options.0.domain.choices Field required".
        result = _call_via_system_python(
            "yunohost.app", "app_install", {"app": app, "label": label, "args": args, "force": force}, self.settings
        )
        return {"fake": False, "operation_id": _latest_operation_id(), "result": result}

    def app_upgrade(
        self,
        app: str | list[str] | None = None,
        force: bool = False,
        file: str | None = None,
        url: str | None = None,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "app.upgrade",
            {"app": app, "force": force, "url": url, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "app": app, "file": file, "url": url, "result": "success"}
        # app_upgrade() is not @is_unit_operation-decorated; it builds its
        # own OperationLogger internally, once per app it actually
        # upgrades, so there's no single id to hand back for a multi-app
        # call - the per-app result dict plus operations_list() cover it.
        # `file` (a local folder or tarball) is what package_upgrade_test
        # uses to upgrade an already-installed app from a candidate source
        # instead of the catalog. `url` is the same idea for an app that
        # isn't in any registered catalog at all (installed via `app
        # install <url>` directly, e.g. this server's own yunohost_mcp
        # app) - without it, real app_upgrade() has no catalog entry to
        # compare against and raises "No apps can be upgraded" even
        # though a newer commit genuinely exists at that url. Both accept
        # only a single app (PHASE0-style check of the real source), same
        # as the real function.
        # Routed via _call_via_system_python for the same reason as
        # app_install() just above - app_upgrade() can re-parse manifest
        # [install] options too (e.g. an upgrade that adds a new question,
        # or reconfirms an existing domain/group one).
        try:
            result = _call_via_system_python(
                "yunohost.app",
                "app_upgrade",
                {"app": app or [], "force": force, "file": file, "url": url},
                self.settings,
            )
        except YunohostUnavailableError as exc:
            # YunoHost reports an already-current app as a subprocess
            # failure ("No apps can be upgraded"). Preserve that expected
            # operational outcome so the broker returns a useful tool error
            # instead of masking it as an internal failure.
            if "no apps can be upgraded" in str(exc).lower():
                raise NoAppsToUpgradeError("nothing to upgrade") from exc
            raise
        return {"fake": False, "app": app, "result": result}

    def app_remove(self, app: str, purge: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call(
            "app.remove", {"app": app, "purge": purge, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-app_remove", "app": app, "purged": purge}
        app_remove = _import_attr("yunohost.app", "app_remove")
        result = app_remove(app, purge=purge)
        return {"fake": False, "operation_id": _latest_operation_id(), "app": app, "result": result}

    def app_change_url(
        self, app: str, domain: str, path: str, confirmation_id: str | None = None
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "app.change_url",
            {"app": app, "domain": domain, "path": path, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "operation_id": "20260903-000000-app_change_url",
                "app": app,
                "domain": domain,
                "path": path,
            }
        # @is_unit_operation-decorated (yunohost.app), same
        # no-manual-operation_logger convention as app_remove just above -
        # but unlike app_remove, it imports yunohost.utils.form
        # (DomainOption, WebPathOption, to normalize/validate the new
        # domain and path) - same pydantic v1/v2 conflict as app_install/
        # domain_add/backup_create, see _call_via_system_python's
        # docstring. Must go through the system-python subprocess too.
        # Returns None on success (the app's own settings are updated
        # in-place, nothing meaningful to hand back beyond the operation
        # id), unlike app_install/app_remove which return a result dict.
        _call_via_system_python(
            "yunohost.app", "app_change_url", {"app": app, "domain": domain, "path": path}, self.settings
        )
        return {"fake": False, "operation_id": _latest_operation_id(), "app": app, "domain": domain, "path": path}

    def backup_restore(
        self,
        name: str,
        apps: list[str] | None = None,
        system: list[str] | None = None,
        force: bool = False,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "backup.restore",
            {"name": name, "apps": apps, "system": system, "force": force, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "name": name, "apps": apps or [], "system": system or []}
        # backup_restore() is not @is_unit_operation-decorated either - no
        # operation id to capture here at all, best-effort or otherwise.
        result = _call_via_system_python(
            "yunohost.backup",
            "backup_restore",
            {"name": name, "system": system or [], "apps": apps or [], "force": force},
            self.settings,
        )
        return {"fake": False, "name": name, "result": result}

    def system_upgrade(self, confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call("system.upgrade", {"confirmation_id": confirmation_id})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "operation_id": "20260903-000000-tools_upgrade", "result": "success"}
        tools_upgrade = _import_attr("yunohost.tools", "tools_upgrade")
        result = tools_upgrade(target="system")
        return {"fake": False, "operation_id": _latest_operation_id(), "result": result}

    # -- Migrations ---------------------------------------------------------
    #
    # None of tools_migrations_{list,run,state} are @is_unit_operation-
    # decorated, and none transitively import yunohost.utils.form - plain
    # _import_attr calls are fine here, same as service_restart/system_upgrade.

    def migrations_list(self, pending: bool = False, done: bool = False) -> dict[str, Any]:
        brokered = self._broker_call("migrations.list", {"pending": pending, "done": done})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "migrations": []}
        tools_migrations_list = _import_attr("yunohost.tools", "tools_migrations_list")
        return {"fake": False, **tools_migrations_list(pending=pending, done=done)}

    def migrations_state(self) -> dict[str, Any]:
        brokered = self._broker_call("migrations.state", {})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "migrations": {}}
        tools_migrations_state = _import_attr("yunohost.tools", "tools_migrations_state")
        return {"fake": False, **tools_migrations_state()}

    def migrations_run(
        self,
        targets: list[str] | None = None,
        skip: bool = False,
        auto: bool = False,
        force_rerun: bool = False,
        accept_disclaimer: bool = False,
        skip_postmigrations: bool = False,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "migrations.run",
            {
                "targets": targets,
                "skip": skip,
                "auto": auto,
                "force_rerun": force_rerun,
                "accept_disclaimer": accept_disclaimer,
                "skip_postmigrations": skip_postmigrations,
                "confirmation_id": confirmation_id,
            },
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "targets": targets or [], "state": {}}
        tools_migrations_run = _import_attr("yunohost.tools", "tools_migrations_run")
        # tools_migrations_run() returns None - like app_upgrade(), it builds
        # its own OperationLogger internally, once per migration it actually
        # runs (not one per call), so there's no single operation id to hand
        # back either. Fetch migrations_state() afterward instead, so the
        # caller gets an immediate, no-second-call picture of what changed
        # rather than having to separately call migrations_state() to find out.
        tools_migrations_run(
            targets=targets or [],
            skip=skip,
            auto=auto,
            force_rerun=force_rerun,
            accept_disclaimer=accept_disclaimer,
            skip_postmigrations=skip_postmigrations,
        )
        tools_migrations_state = _import_attr("yunohost.tools", "tools_migrations_state")
        return {"fake": False, "targets": targets or [], "state": tools_migrations_state()}

    # -- Firewall -------------------------------------------------------------
    #
    # firewall_{list,is_open,open,close,reload} are all plain functions - not
    # @is_unit_operation-decorated, no transitive yunohost.utils.form import -
    # same in-process _import_attr pattern as service_restart. Wraps the
    # current (non-"Legacy API") firewall_open/firewall_close rather than the
    # older firewall_allow/firewall_disallow aliases the yunohost source
    # itself labels legacy - same effect, current API.

    def firewall_list(
        self, raw: bool = False, protocol: str = "tcp", forwarded: bool = False
    ) -> dict[str, Any]:
        brokered = self._broker_call("firewall.list", {"raw": raw, "protocol": protocol, "forwarded": forwarded})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, protocol: []}
        firewall_list = _import_attr("yunohost.firewall", "firewall_list")
        return {"fake": False, **firewall_list(raw=raw, protocol=protocol, forwarded=forwarded)}

    def firewall_is_open(self, port: int | str, protocol: str) -> dict[str, Any]:
        brokered = self._broker_call("firewall.is_open", {"port": port, "protocol": protocol})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "port": port, "protocol": protocol, "open": False}
        firewall_is_open = _import_attr("yunohost.firewall", "firewall_is_open")
        return {
            "fake": False,
            "port": port,
            "protocol": protocol,
            "open": firewall_is_open(port, protocol),
        }

    def firewall_open(
        self,
        port: int | str,
        protocol: str,
        comment: str = "",
        upnp: bool = False,
        no_reload: bool = False,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "firewall.open",
            {"port": port, "protocol": protocol, "comment": comment, "upnp": upnp, "no_reload": no_reload, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "port": port, "protocol": protocol}
        firewall_open = _import_attr("yunohost.firewall", "firewall_open")
        firewall_open(port, protocol, comment, upnp=upnp, no_reload=no_reload)
        return {"fake": False, "port": port, "protocol": protocol}

    def firewall_close(
        self,
        port: int | str,
        protocol: str,
        upnp_only: bool = False,
        no_reload: bool = False,
        confirmation_id: str | None = None,
    ) -> dict[str, Any]:
        brokered = self._broker_call(
            "firewall.close",
            {"port": port, "protocol": protocol, "upnp_only": upnp_only, "no_reload": no_reload, "confirmation_id": confirmation_id},
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "port": port, "protocol": protocol}
        firewall_close = _import_attr("yunohost.firewall", "firewall_close")
        firewall_close(port, protocol, upnp_only=upnp_only, no_reload=no_reload)
        return {"fake": False, "port": port, "protocol": protocol}

    def firewall_reload(self, skip_upnp: bool = False, confirmation_id: str | None = None) -> dict[str, Any]:
        brokered = self._broker_call(
            "firewall.reload", {"skip_upnp": skip_upnp, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "reloaded": True}
        firewall_reload = _import_attr("yunohost.firewall", "firewall_reload")
        firewall_reload(skip_upnp=skip_upnp)
        return {"fake": False, "reloaded": True}

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
        brokered = self._broker_call("package.inspect", {"source": source})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "id": "example",
                "packaging_format": 2,
                "resources": {"system_user": {}, "install_dir": {}, "permissions": {}},
                "unknown_resource_types": [],
            }
        # app_manifest() imports yunohost.utils.form (for its "install"
        # questions field), which hits the same pydantic v1/v2 conflict as
        # backup_create/backup_restore (see _call_via_system_python's
        # docstring) - route it through the same subprocess.
        manifest = _call_via_system_python("yunohost.app", "app_manifest", {"app": source}, self.settings)
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
        brokered = self._broker_call("package.lint", {"source": source})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("catalog.package_inspect", {"source": source, "ref": ref})
        if brokered is not None:
            return brokered
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
                raise ToolInputError("remote catalogue package sources must use HTTPS")
            args = ["preview"]
            if ref:
                args += ["--ref", ref]
            args.append(source)
            return {"fake": False, **self._run_catalog_json(args)}
        package = self.package_inspect(source)
        return {"fake": False, "source": str(Path(source).resolve()), **package}

    def catalog_publish_plan(self, source: str, ref: str | None = None) -> dict[str, Any]:
        """Build and sign a declaration locally, without contacting relays."""
        brokered = self._broker_call("catalog.publish_plan", {"source": source, "ref": ref})
        if brokered is not None:
            return brokered
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

    def catalog_publish(
        self, source: str, ref: str | None = None, confirmation_id: str | None = None, plan_id: str | None = None
    ) -> dict[str, Any]:
        """Publish a previously planned package declaration to configured relays."""
        brokered = self._broker_call(
            "catalog.publish",
            {"source": source, "ref": ref, "confirmation_id": confirmation_id, "plan_id": plan_id},
        )
        if brokered is not None:
            return brokered
        self._validate_catalog_source(source, ref)
        relays = self._catalog_relays()
        if not relays:
            raise ToolInputError("catalog_relays must contain at least one relay URL")
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
        brokered = self._broker_call("catalog.verify", {"event_or_naddr": event_or_naddr})
        if brokered is not None:
            return brokered
        if self.settings.fake_yunohost:
            return {"fake": True, "valid": True, "value": event_or_naddr}
        if event_or_naddr.startswith("naddr"):
            return {"fake": False, **self._run_catalog_json(["inspect", "--json", event_or_naddr])}
        try:
            event = json.loads(event_or_naddr)
        except json.JSONDecodeError as exc:
            raise ToolInputError("event_or_naddr must be a JSON event or naddr") from exc
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            json.dump(event, handle)
            event_path = handle.name
        try:
            return {"fake": False, **self._run_catalog_json(["verify", "--json", event_path])}
        finally:
            Path(event_path).unlink(missing_ok=True)

    def catalog_list(self) -> dict[str, Any]:
        """The whole Nostr-catalogue snapshot (every declared app, not just
        this server's own), built the same way nostr-catalogd's own
        /v3/apps.json is: fetch every kind-30078 declaration from the
        configured relays, apply the trusted-publisher policy for any app
        id with more than one candidate declaration, keep the newest per
        app id. Read-only - the CLI's own `catalog` subcommand does the
        relay round trip; nothing here signs or publishes anything.
        """
        brokered = self._broker_call("catalog.list", {})
        if brokered is not None:
            return brokered
        relays = self._catalog_relays()
        if self.settings.fake_yunohost:
            return {
                "fake": True,
                "relays": relays,
                "apps": {
                    "example": {"id": "example", "name": "Example", "version": "1.0~ynh1"},
                },
            }
        if not relays:
            raise ToolInputError("catalog_relays must contain at least one relay URL")
        args = ["catalog", "--relays", ",".join(relays)]
        trusted_publishers = self._catalog_trusted_publishers()
        if trusted_publishers:
            args += ["--trusted-publishers", ",".join(trusted_publishers)]
        result = self._run_catalog_json(args)
        return {"fake": False, "relays": relays, **result}

    def _catalog_relays(self) -> list[str]:
        relays = [relay.strip() for relay in self.settings.catalog_relays.split(",") if relay.strip()]
        if relays:
            return relays
        return self._read_nostr_catalog_ynh_env("NOSTR_YNH_RELAYS")

    def _catalog_trusted_publishers(self) -> list[str]:
        publishers = [p.strip() for p in self.settings.catalog_trusted_publishers.split(",") if p.strip()]
        if publishers:
            return publishers
        return self._read_nostr_catalog_ynh_env("NOSTR_YNH_TRUSTED_PUBLISHERS")

    def _read_nostr_catalog_ynh_env(self, key: str) -> list[str]:
        # Falls back to nostr_catalog_ynh's own env file (written by its
        # render_daemon_env, see scripts/_common.sh) so this app doesn't
        # need a second, separately-maintained copy of its relay list or
        # trusted-publisher set - see config.py's catalog_relays_env_path
        # docstring. Same file backs both NOSTR_YNH_RELAYS and
        # NOSTR_YNH_TRUSTED_PUBLISHERS.
        env_path = self.settings.catalog_relays_env_path
        try:
            content = env_path.read_text()
        except OSError:
            return []
        prefix = f"{key}="
        for line in content.splitlines():
            if not line.startswith(prefix):
                continue
            value = line[len(prefix) :].strip()
            return [item.strip() for item in value.split(",") if item.strip()]
        return []

    def _validate_catalog_source(self, source: str, ref: str | None) -> None:
        if ref is not None:
            if not source.startswith("https://"):
                raise ToolInputError("a ref may only be used with an HTTPS remote repository")
            if not ref.strip():
                raise ToolInputError("remote repository ref must not be empty")
            return
        if source.startswith(("https://", "http://")):
            if not source.startswith("https://"):
                raise ToolInputError("remote catalogue package sources must use HTTPS")
            if self.settings.catalog_require_remote_ref:
                raise ToolInputError("an explicit ref is required for remote catalogue sources")
            return
        path = Path(source)
        if not path.exists() or not path.is_dir():
            raise ToolInputError("local catalogue source must be an existing directory")

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
        brokered = self._broker_call("package.install_test", {"source": source, "label": label, "args": args})
        if brokered is not None:
            return brokered
        return self.app_install(source, label=label, args=args, force=True)

    def package_upgrade_test(self, app: str, source: str) -> dict[str, Any]:
        """Upgrade an already-installed `app` from a candidate `source`
        (local path/tarball) instead of the catalog."""
        brokered = self._broker_call("package.upgrade_test", {"app": app, "source": source})
        if brokered is not None:
            return brokered
        return self.app_upgrade(app=app, file=source, force=True)

    def package_backup_test(self, app: str) -> dict[str, Any]:
        brokered = self._broker_call("package.backup_test", {"app": app})
        if brokered is not None:
            return brokered
        return self.backup_create(name=f"package-test-{app}", apps=[app])

    def package_restore_test(self, app: str, archive_name: str) -> dict[str, Any]:
        brokered = self._broker_call("package.restore_test", {"app": app, "archive_name": archive_name})
        if brokered is not None:
            return brokered
        return self.backup_restore(archive_name, apps=[app], force=True)

    def package_change_url_test(self, app: str, domain: str, path: str) -> dict[str, Any]:
        brokered = self._broker_call(
            "package.change_url_test", {"app": app, "domain": domain, "path": path}
        )
        if brokered is not None:
            return brokered
        return self.app_change_url(app, domain, path)

    def package_remove_test(self, app: str, purge: bool = True) -> dict[str, Any]:
        brokered = self._broker_call("package.remove_test", {"app": app, "purge": purge})
        if brokered is not None:
            return brokered
        return self.app_remove(app, purge=purge)

    def package_run_tests(
        self, source: str, app_id: str | None = None, confirmation_id: str | None = None
    ) -> dict[str, Any]:
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
        brokered = self._broker_call(
            "package.run_tests", {"source": source, "app_id": app_id, "confirmation_id": confirmation_id}
        )
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("diagnose.app", {"app": app})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("validate.server", {})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("safe.upgrade", {"app": app})
        if brokered is not None:
            return brokered
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
        brokered = self._broker_call("repair.app", {"app": app, "strategy": strategy})
        if brokered is not None:
            return brokered
        if strategy != "conservative":
            raise ToolInputError(f"unknown repair strategy {strategy!r}; only 'conservative' is implemented")

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


_JOURNAL_PRIORITY_NAMES = {
    "0": "emerg",
    "1": "alert",
    "2": "crit",
    "3": "err",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "debug",
}


def _normalize_journal_entry(raw: dict[str, Any], *, default_service: str) -> dict[str, Any]:
    """One `journalctl -o json` record -> {timestamp, service, priority,
    message}. __REALTIME_TIMESTAMP is microseconds since the epoch, as a
    decimal string; PRIORITY is a syslog priority number 0-7, also a
    string; MESSAGE is normally a string but journalctl encodes a
    non-UTF8 one as a JSON array of byte values instead - handle both.

    `message` passes through redact_text() - a service's own journal
    output can carry KEY=VALUE-shaped secrets the same way an operation
    log's shell trace can (see operation_logs()'s docstring for why
    redact_response's key-based redaction can't reach this either)."""
    import datetime as _dt

    timestamp = raw.get("__REALTIME_TIMESTAMP")
    if timestamp is not None:
        try:
            timestamp = _dt.datetime.fromtimestamp(int(timestamp) / 1_000_000, tz=_dt.timezone.utc).isoformat()
        except (ValueError, OverflowError):
            timestamp = None

    message = raw.get("MESSAGE", "")
    if isinstance(message, list):
        message = bytes(message).decode("utf-8", errors="replace")
    if isinstance(message, str):
        message = redact_text(message)

    return {
        "timestamp": timestamp,
        "service": raw.get("_SYSTEMD_UNIT", default_service),
        "priority": _JOURNAL_PRIORITY_NAMES.get(str(raw.get("PRIORITY")), raw.get("PRIORITY")),
        "message": message,
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
