"""Fixed operation registry for the privileged helper.

There is deliberately no generic callable, command, module, or executable
path in this registry.  Adding a privileged capability requires an explicit
entry and an adapter method with a bounded argument schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from yunohost_mcp.yunohost.adapter import YunohostAdapter


@dataclass(frozen=True)
class BrokerOperation:
    name: str
    required_scope: str
    invoke: Callable[[YunohostAdapter, dict[str, Any]], dict[str, Any]]


def _no_args(fn):
    def invoke(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
        if arguments:
            raise ValueError("operation does not accept arguments")
        return fn(adapter)

    return invoke


def _service_status(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    names = arguments.get("names", [])
    if not isinstance(names, list) or not all(isinstance(name, str) and name for name in names):
        raise ValueError("names must be a list of non-empty strings")
    if len(names) > 128:
        raise ValueError("too many services")
    return adapter.service_status(names)


def _apps_list(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    full = arguments.get("full", False)
    if not isinstance(full, bool):
        raise ValueError("full must be a boolean")
    return adapter.apps_list(full=full)


def _app_info(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    app = arguments.get("app")
    full = arguments.get("full", False)
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a non-empty string")
    if not isinstance(full, bool):
        raise ValueError("full must be a boolean")
    return adapter.app_info(app, full=full)


def _app_resources(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    app = arguments.get("app")
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a non-empty string")
    return adapter.app_resources(app)


def _app_config_get(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    app = arguments.get("app")
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a non-empty string")
    values = {key: arguments.get(key, default) for key, default in (("key", ""), ("full", False), ("export", False))}
    if not isinstance(values["key"], str) or not all(isinstance(values[key], bool) for key in ("full", "export")):
        raise ValueError("invalid app config arguments")
    return adapter.app_config_get(app, **values)


def _free_space(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    path = arguments.get("path", "/")
    if not isinstance(path, str) or path not in {"/", "/home", "/var"}:
        raise ValueError("path must be one of the supported filesystem roots")
    return {"free_bytes": adapter.free_space_bytes(path)}


def _backup_times(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if arguments:
        raise ValueError("operation does not accept arguments")
    return {"created_at": adapter.backup_created_at_times()}


def _operations_list(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    limit = arguments.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000):
        raise ValueError("limit must be between 1 and 1000")
    return adapter.operations_list(limit=limit)


def _operation_name(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    name = arguments.get("name")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ValueError("name must be a non-empty string")
    return adapter.operation_status(name)


def _operation_logs(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    name = arguments.get("name")
    tail_lines = arguments.get("tail_lines")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ValueError("name must be a non-empty string")
    if tail_lines is not None and (not isinstance(tail_lines, int) or isinstance(tail_lines, bool) or not 1 <= tail_lines <= 10000):
        raise ValueError("tail_lines must be between 1 and 10000")
    return adapter.operation_logs(name, tail_lines=tail_lines)


def _domain_name(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    domain = arguments.get("domain")
    if not isinstance(domain, str) or not domain or len(domain) > 253:
        raise ValueError("domain must be a non-empty string")
    return adapter.domain_cert_info(domain)


def _service_logs(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    service = arguments.get("service")
    if not isinstance(service, str) or not service or len(service) > 128:
        raise ValueError("service must be a non-empty string")
    lines = arguments.get("lines", 200)
    if not isinstance(lines, int) or isinstance(lines, bool) or not 1 <= lines <= 2000:
        raise ValueError("lines must be between 1 and 2000")
    optional = {key: arguments.get(key) for key in ("since", "until", "priority", "grep")}
    if any(value is not None and not isinstance(value, str) for value in optional.values()):
        raise ValueError("service log filters must be strings")
    return adapter.service_logs(service, lines=lines, **optional)


def _updates_check(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if arguments:
        raise ValueError("operation does not accept arguments")
    return adapter.updates_check()


def _updates_refresh(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"target"}:
        raise ValueError("unknown updates refresh argument")
    target = arguments.get("target", "apps")
    if not isinstance(target, str) or target not in {"system", "apps", "all"}:
        raise ValueError("target must be one of: system, apps, all")
    return adapter.updates_refresh(target=target)


def _diagnosis_run(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"categories", "force"}:
        raise ValueError("unknown diagnosis argument")
    categories = arguments.get("categories")
    if categories is not None and (
        not isinstance(categories, list)
        or len(categories) > 64
        or not all(isinstance(category, str) and 0 < len(category) <= 128 for category in categories)
    ):
        raise ValueError("categories must be a bounded list of non-empty strings")
    force = arguments.get("force", False)
    if not isinstance(force, bool):
        raise ValueError("force must be a boolean")
    return adapter.diagnosis_run(categories=categories, force=force)


def _catalog_package_inspect(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"source", "ref"}:
        raise ValueError("unknown catalog inspection argument")
    source = arguments.get("source")
    ref = arguments.get("ref")
    if not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("source must be a bounded non-empty string")
    if ref is not None and (not isinstance(ref, str) or len(ref) > 256):
        raise ValueError("ref must be a bounded string")
    return adapter.catalog_package_inspect(source, ref=ref)


def _catalog_verify(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) != {"event_or_naddr"}:
        raise ValueError("event_or_naddr is required")
    value = arguments["event_or_naddr"]
    if not isinstance(value, str) or not value or len(value) > 1_000_000:
        raise ValueError("event_or_naddr must be a bounded non-empty string")
    return adapter.catalog_verify(value)


def _catalog_publish_plan(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"source", "ref"}:
        raise ValueError("unknown catalog publish-plan argument")
    source = arguments.get("source")
    ref = arguments.get("ref")
    if not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("source must be a bounded non-empty string")
    if ref is not None and (not isinstance(ref, str) or len(ref) > 256):
        raise ValueError("ref must be a bounded string")
    return adapter.catalog_publish_plan(source, ref=ref)


def _catalog_publish(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"source", "ref", "confirmation_id", "plan_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown catalog publish argument")
    source = arguments.get("source")
    ref = arguments.get("ref")
    if not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("source must be a bounded non-empty string")
    if ref is not None and (not isinstance(ref, str) or len(ref) > 256):
        raise ValueError("ref must be a bounded string")
    for key in ("confirmation_id", "plan_id"):
        value = arguments.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 128):
            raise ValueError(f"{key} must be a string")
    return adapter.catalog_publish(
        source=source,
        ref=ref,
        confirmation_id=arguments.get("confirmation_id"),
        plan_id=arguments.get("plan_id"),
    )


def _package_source(arguments: dict[str, Any], operation: str) -> str:
    if set(arguments) != {"source"}:
        raise ValueError(f"{operation} accepts only source")
    source = arguments["source"]
    if not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("source must be a bounded non-empty string")
    return source


def _package_inspect(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    return adapter.package_inspect(_package_source(arguments, "package.inspect"))


def _package_lint(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    return adapter.package_lint(_package_source(arguments, "package.lint"))


def _package_run_tests(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"source", "app_id", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown package test argument")
    source = arguments.get("source")
    app_id = arguments.get("app_id")
    if not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("source must be a bounded non-empty string")
    if app_id is not None and (not isinstance(app_id, str) or not app_id or len(app_id) > 128):
        raise ValueError("app_id must be a bounded string")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.package_run_tests(source, app_id=app_id, confirmation_id=confirmation_id)


def _package_install_test(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"source", "label", "args"}
    if set(arguments) - allowed:
        raise ValueError("unknown package install-test argument")
    source = arguments.get("source")
    if not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("source must be a bounded non-empty string")
    for key in ("label", "args"):
        if arguments.get(key) is not None and (not isinstance(arguments[key], str) or len(arguments[key]) > 8192):
            raise ValueError(f"{key} must be a bounded string")
    return adapter.package_install_test(source, label=arguments.get("label"), args=arguments.get("args"))


def _package_upgrade_test(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"app", "source"}
    if set(arguments) != allowed:
        raise ValueError("app and source are required")
    app, source = arguments["app"], arguments["source"]
    if not isinstance(app, str) or not app or len(app) > 128 or not isinstance(source, str) or not source or len(source) > 8192:
        raise ValueError("app and source must be bounded non-empty strings")
    return adapter.package_upgrade_test(app, source)


def _package_backup_test(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) != {"app"}:
        raise ValueError("app is required")
    app = arguments["app"]
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a bounded non-empty string")
    return adapter.package_backup_test(app)


def _package_restore_test(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) != {"app", "archive_name"}:
        raise ValueError("app and archive_name are required")
    app, archive = arguments["app"], arguments["archive_name"]
    if not all(isinstance(value, str) and value and len(value) <= 256 for value in (app, archive)):
        raise ValueError("app and archive_name must be bounded non-empty strings")
    return adapter.package_restore_test(app, archive)


def _package_change_url_test(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) != {"app", "domain", "path"}:
        raise ValueError("app, domain, and path are required")
    if not all(isinstance(arguments[key], str) and arguments[key] and len(arguments[key]) <= 8192 for key in arguments):
        raise ValueError("package change-url arguments must be bounded non-empty strings")
    return adapter.package_change_url_test(arguments["app"], arguments["domain"], arguments["path"])


def _package_remove_test(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"app", "purge"}:
        raise ValueError("unknown package remove-test argument")
    app, purge = arguments.get("app"), arguments.get("purge", True)
    if not isinstance(app, str) or not app or len(app) > 128 or not isinstance(purge, bool):
        raise ValueError("app and purge are invalid")
    return adapter.package_remove_test(app, purge=purge)


def _safe_upgrade(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) != {"app"}:
        raise ValueError("app is required")
    app = arguments["app"]
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a bounded non-empty string")
    return adapter.safe_upgrade(app)


def _repair_app(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"app", "strategy"}:
        raise ValueError("unknown repair argument")
    app, strategy = arguments.get("app"), arguments.get("strategy", "conservative")
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a bounded non-empty string")
    if strategy != "conservative":
        raise ValueError("only the conservative repair strategy is supported")
    return adapter.repair_app(app, strategy=strategy)


def _diagnose_app(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) != {"app"}:
        raise ValueError("app is required")
    app = arguments["app"]
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a bounded non-empty string")
    return adapter.diagnose_app(app)


def _migrations_list(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    pending, done = arguments.get("pending", False), arguments.get("done", False)
    if not isinstance(pending, bool) or not isinstance(done, bool):
        raise ValueError("pending and done must be booleans")
    return adapter.migrations_list(pending=pending, done=done)


def _firewall_list(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    raw, protocol, forwarded = arguments.get("raw", False), arguments.get("protocol", "tcp"), arguments.get("forwarded", False)
    if not isinstance(raw, bool) or not isinstance(forwarded, bool) or not isinstance(protocol, str):
        raise ValueError("invalid firewall list arguments")
    return adapter.firewall_list(raw=raw, protocol=protocol, forwarded=forwarded)


def _firewall_is_open(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    port, protocol = arguments.get("port"), arguments.get("protocol")
    if not isinstance(port, (int, str)) or isinstance(port, bool) or not isinstance(protocol, str):
        raise ValueError("port and protocol are required")
    return adapter.firewall_is_open(port, protocol)


def _service_restart(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"names", "confirmation_id"}:
        raise ValueError("unknown service restart argument")
    names = arguments.get("names")
    if not isinstance(names, list) or not names or len(names) > 16 or not all(isinstance(name, str) and name for name in names):
        raise ValueError("names must contain 1 to 16 non-empty service names")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.service_restart(names, confirmation_id=confirmation_id)


def _backup_create(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"name", "description", "apps", "system", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown backup argument")
    for key in ("name", "description"):
        if arguments.get(key) is not None and not isinstance(arguments[key], str):
            raise ValueError(f"{key} must be a string")
    for key in ("apps", "system"):
        value = arguments.get(key)
        if value is not None and (not isinstance(value, list) or len(value) > 128 or not all(isinstance(item, str) for item in value)):
            raise ValueError(f"{key} must be a list of strings")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.backup_create(
        name=arguments.get("name"),
        description=arguments.get("description"),
        apps=arguments.get("apps"),
        system=arguments.get("system"),
        confirmation_id=confirmation_id,
    )


def _app_install(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"app", "label", "args", "force", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown app install argument")
    app = arguments.get("app")
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a non-empty string")
    for key in ("label", "args"):
        if arguments.get(key) is not None and (not isinstance(arguments[key], str) or len(arguments[key]) > 8192):
            raise ValueError(f"{key} must be a string of at most 8192 characters")
    force = arguments.get("force", False)
    if not isinstance(force, bool):
        raise ValueError("force must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.app_install(
        app, label=arguments.get("label"), args=arguments.get("args"), force=force, confirmation_id=confirmation_id
    )


def _app_upgrade(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"app", "force", "url", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown app upgrade argument")
    app = arguments.get("app")
    if app is not None and not (
        isinstance(app, (str, list))
        and (isinstance(app, str) or all(isinstance(item, str) and item for item in app))
    ):
        raise ValueError("app must be a string, a list of strings, or null")
    if isinstance(app, str) and (not app or len(app) > 128):
        raise ValueError("app must be a non-empty string")
    if isinstance(app, list) and (not app or len(app) > 128 or any(len(item) > 128 for item in app)):
        raise ValueError("app list must contain 1 to 128 bounded names")
    force = arguments.get("force", False)
    if not isinstance(force, bool):
        raise ValueError("force must be a boolean")
    url = arguments.get("url")
    if url is not None and (not isinstance(url, str) or len(url) > 8192):
        raise ValueError("url must be a string of at most 8192 characters")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.app_upgrade(app=app, force=force, url=url, confirmation_id=confirmation_id)


def _app_remove(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"app", "purge", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown app removal argument")
    app = arguments.get("app")
    if not isinstance(app, str) or not app or len(app) > 128:
        raise ValueError("app must be a non-empty string")
    purge = arguments.get("purge", False)
    if not isinstance(purge, bool):
        raise ValueError("purge must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.app_remove(app, purge=purge, confirmation_id=confirmation_id)


def _app_change_url(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"app", "domain", "path", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown app URL argument")
    for key, max_length in (("app", 128), ("domain", 253), ("path", 4096)):
        value = arguments.get(key)
        if not isinstance(value, str) or not value or len(value) > max_length:
            raise ValueError(f"{key} must be a non-empty bounded string")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.app_change_url(
        arguments["app"], arguments["domain"], arguments["path"], confirmation_id=confirmation_id
    )


def _app_config_set(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"app", "key", "value", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown app config argument")
    for name, max_length in (("app", 128), ("key", 512), ("value", 8192)):
        value = arguments.get(name)
        if not isinstance(value, str) or not value or len(value) > max_length:
            raise ValueError(f"{name} must be a non-empty bounded string")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.app_config_set(
        arguments["app"], arguments["key"], arguments["value"], confirmation_id=confirmation_id
    )


def _backup_restore(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"name", "apps", "system", "force", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown backup restore argument")
    name = arguments.get("name")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ValueError("name must be a non-empty string")
    for key in ("apps", "system"):
        value = arguments.get(key)
        if value is not None and (
            not isinstance(value, list)
            or len(value) > 128
            or not all(isinstance(item, str) and item for item in value)
        ):
            raise ValueError(f"{key} must be a list of non-empty strings")
    force = arguments.get("force", False)
    if not isinstance(force, bool):
        raise ValueError("force must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.backup_restore(
        name, apps=arguments.get("apps"), system=arguments.get("system"), force=force,
        confirmation_id=confirmation_id,
    )


def _system_upgrade(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"confirmation_id"}:
        raise ValueError("unknown system upgrade argument")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.system_upgrade(confirmation_id=confirmation_id)


def _migrations_run(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "targets", "skip", "auto", "force_rerun", "accept_disclaimer", "skip_postmigrations", "confirmation_id"
    }
    if set(arguments) - allowed:
        raise ValueError("unknown migration argument")
    targets = arguments.get("targets")
    if targets is not None and (
        not isinstance(targets, list)
        or len(targets) > 128
        or not all(isinstance(item, str) and item and len(item) <= 256 for item in targets)
    ):
        raise ValueError("targets must be a list of bounded non-empty strings")
    flags = ("skip", "auto", "force_rerun", "accept_disclaimer", "skip_postmigrations")
    if any(not isinstance(arguments.get(flag, False), bool) for flag in flags):
        raise ValueError("migration flags must be booleans")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.migrations_run(
        targets=targets,
        **{flag: arguments.get(flag, False) for flag in flags},
        confirmation_id=confirmation_id,
    )


def _port_and_protocol(arguments: dict[str, Any]) -> tuple[int | str, str]:
    port = arguments.get("port")
    if isinstance(port, bool) or not isinstance(port, (int, str)):
        raise ValueError("port must be an integer or range string")
    if isinstance(port, int) and not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if isinstance(port, str) and (
        len(port) > 11 or not port or any(not part.isdigit() or not 1 <= int(part) <= 65535 for part in port.split("-"))
    ):
        raise ValueError("port must be a valid port or port range")
    protocol = arguments.get("protocol")
    if protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be tcp or udp")
    return port, protocol


def _firewall_open(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"port", "protocol", "comment", "upnp", "no_reload", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown firewall open argument")
    port, protocol = _port_and_protocol(arguments)
    comment = arguments.get("comment", "")
    if not isinstance(comment, str) or len(comment) > 1024:
        raise ValueError("comment must be a string of at most 1024 characters")
    for flag in ("upnp", "no_reload"):
        if not isinstance(arguments.get(flag, False), bool):
            raise ValueError(f"{flag} must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.firewall_open(port, protocol, comment=comment, upnp=arguments.get("upnp", False), no_reload=arguments.get("no_reload", False), confirmation_id=confirmation_id)


def _firewall_close(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"port", "protocol", "upnp_only", "no_reload", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown firewall close argument")
    port, protocol = _port_and_protocol(arguments)
    for flag in ("upnp_only", "no_reload"):
        if not isinstance(arguments.get(flag, False), bool):
            raise ValueError(f"{flag} must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.firewall_close(port, protocol, upnp_only=arguments.get("upnp_only", False), no_reload=arguments.get("no_reload", False), confirmation_id=confirmation_id)


def _firewall_reload(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    if set(arguments) - {"skip_upnp", "confirmation_id"}:
        raise ValueError("unknown firewall reload argument")
    if not isinstance(arguments.get("skip_upnp", False), bool):
        raise ValueError("skip_upnp must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.firewall_reload(skip_upnp=arguments.get("skip_upnp", False), confirmation_id=confirmation_id)


def _bounded_string(arguments: dict[str, Any], key: str, limit: int, *, required: bool = False) -> str | None:
    value = arguments.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"{key} must be a non-empty string of at most {limit} characters")
    return value


def _user_create(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"username", "domain", "password", "fullname", "mailbox_quota", "admin", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown user create argument")
    username = _bounded_string(arguments, "username", 128, required=True)
    domain = _bounded_string(arguments, "domain", 253, required=True)
    password = _bounded_string(arguments, "password", 4096, required=True)
    fullname = _bounded_string(arguments, "fullname", 512, required=True)
    quota = arguments.get("mailbox_quota", "0")
    if quota is not None and (not isinstance(quota, str) or len(quota) > 64):
        raise ValueError("mailbox_quota must be a bounded string or null")
    admin = arguments.get("admin", False)
    if not isinstance(admin, bool):
        raise ValueError("admin must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.user_create(username, domain=domain, password=password, fullname=fullname, mailbox_quota=quota, admin=admin, confirmation_id=confirmation_id)


def _user_update(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"username", "mail", "change_password", "add_mailforward", "remove_mailforward", "add_mailalias", "remove_mailalias", "mailbox_quota", "fullname", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown user update argument")
    username = _bounded_string(arguments, "username", 128, required=True)
    for key, limit in (("mail", 512), ("change_password", 4096), ("mailbox_quota", 64), ("fullname", 512)):
        _bounded_string(arguments, key, limit)
    for key in ("add_mailforward", "remove_mailforward", "add_mailalias", "remove_mailalias"):
        value = arguments.get(key)
        if value is not None and (not isinstance(value, list) or len(value) > 128 or not all(isinstance(item, str) and item and len(item) <= 512 for item in value)):
            raise ValueError(f"{key} must be a list of bounded non-empty strings")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    values = {key: arguments.get(key) for key in allowed if key not in {"username", "confirmation_id"}}
    return adapter.user_update(username, **values, confirmation_id=confirmation_id)


def _user_delete(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"username", "purge", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown user delete argument")
    username = _bounded_string(arguments, "username", 128, required=True)
    purge = arguments.get("purge", False)
    if not isinstance(purge, bool):
        raise ValueError("purge must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.user_delete(username, purge=purge, confirmation_id=confirmation_id)


def _group_args(arguments: dict[str, Any], keys: set[str]) -> tuple[str, str | None]:
    if set(arguments) - keys:
        raise ValueError("unknown user group argument")
    groupname = _bounded_string(arguments, "groupname", 128, required=True)
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return groupname, confirmation_id


def _group_create(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    groupname, confirmation_id = _group_args(arguments, {"groupname", "confirmation_id"})
    return adapter.user_group_create(groupname, confirmation_id=confirmation_id)


def _group_update(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    groupname, confirmation_id = _group_args(arguments, {"groupname", "add", "remove", "confirmation_id"})
    for key in ("add", "remove"):
        value = arguments.get(key)
        if value is not None and (not isinstance(value, list) or len(value) > 128 or not all(isinstance(item, str) and item and len(item) <= 128 for item in value)):
            raise ValueError(f"{key} must be a list of bounded non-empty usernames")
    return adapter.user_group_update(groupname, add=arguments.get("add"), remove=arguments.get("remove"), confirmation_id=confirmation_id)


def _group_delete(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    groupname, confirmation_id = _group_args(arguments, {"groupname", "confirmation_id"})
    return adapter.user_group_delete(groupname, confirmation_id=confirmation_id)


def _permission_change(adapter: YunohostAdapter, arguments: dict[str, Any], operation: str) -> dict[str, Any]:
    if set(arguments) - {"permission", "names", "confirmation_id"}:
        raise ValueError("unknown user permission argument")
    permission = _bounded_string(arguments, "permission", 256, required=True)
    names = arguments.get("names")
    if not isinstance(names, list) or not 1 <= len(names) <= 128 or not all(
        isinstance(item, str) and item and len(item) <= 128 for item in names
    ):
        raise ValueError("names must contain 1 to 128 bounded non-empty users or groups")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    fn = adapter.user_permission_add if operation == "add" else adapter.user_permission_remove
    return fn(permission, names, confirmation_id=confirmation_id)


def _permission_add(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    return _permission_change(adapter, arguments, "add")


def _permission_remove(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    return _permission_change(adapter, arguments, "remove")


def _domain_add(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"domain", "install_letsencrypt_cert", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown domain add argument")
    domain = _bounded_string(arguments, "domain", 253, required=True)
    letsencrypt = arguments.get("install_letsencrypt_cert", False)
    if not isinstance(letsencrypt, bool):
        raise ValueError("install_letsencrypt_cert must be a boolean")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.domain_add(domain, install_letsencrypt_cert=letsencrypt, confirmation_id=confirmation_id)


def _domain_cert_install(adapter: YunohostAdapter, arguments: dict[str, Any]) -> dict[str, Any]:
    allowed = {"domain", "letsencrypt", "staging", "confirmation_id"}
    if set(arguments) - allowed:
        raise ValueError("unknown domain certificate argument")
    domain = _bounded_string(arguments, "domain", 253, required=True)
    letsencrypt = arguments.get("letsencrypt", True)
    staging = arguments.get("staging", False)
    if not isinstance(letsencrypt, bool) or not isinstance(staging, bool):
        raise ValueError("letsencrypt and staging must be booleans")
    confirmation_id = arguments.get("confirmation_id")
    if confirmation_id is not None and (not isinstance(confirmation_id, str) or len(confirmation_id) > 128):
        raise ValueError("confirmation_id must be a string")
    return adapter.domain_cert_install(
        domain, letsencrypt=letsencrypt, staging=staging, confirmation_id=confirmation_id
    )


OPERATIONS: dict[str, BrokerOperation] = {
    "server.info": BrokerOperation("server.info", "server.read", _no_args(YunohostAdapter.server_info)),
    "health.check": BrokerOperation("health.check", "diagnosis.read", _no_args(YunohostAdapter.health_check)),
    "diagnosis.run": BrokerOperation("diagnosis.run", "diagnosis.read", _diagnosis_run),
    "catalog.package_inspect": BrokerOperation("catalog.package_inspect", "catalog.inspect", _catalog_package_inspect),
    "catalog.verify": BrokerOperation("catalog.verify", "catalog.verify", _catalog_verify),
    "catalog.list": BrokerOperation("catalog.list", "catalog.inspect", _no_args(YunohostAdapter.catalog_list)),
    "catalog.publish_plan": BrokerOperation("catalog.publish_plan", "catalog.inspect", _catalog_publish_plan),
    "catalog.publish": BrokerOperation("catalog.publish", "catalog.publish", _catalog_publish),
    "package.inspect": BrokerOperation("package.inspect", "packages.inspect", _package_inspect),
    "package.lint": BrokerOperation("package.lint", "packages.inspect", _package_lint),
    "package.run_tests": BrokerOperation("package.run_tests", "packages.test", _package_run_tests),
    "package.install_test": BrokerOperation("package.install_test", "packages.test", _package_install_test),
    "package.upgrade_test": BrokerOperation("package.upgrade_test", "packages.test", _package_upgrade_test),
    "package.backup_test": BrokerOperation("package.backup_test", "packages.test", _package_backup_test),
    "package.restore_test": BrokerOperation("package.restore_test", "packages.test", _package_restore_test),
    "package.change_url_test": BrokerOperation("package.change_url_test", "packages.test", _package_change_url_test),
    "package.remove_test": BrokerOperation("package.remove_test", "packages.test", _package_remove_test),
    "safe.upgrade": BrokerOperation("safe.upgrade", "apps.upgrade", _safe_upgrade),
    "repair.app": BrokerOperation("repair.app", "services.restart", _repair_app),
    "diagnose.app": BrokerOperation("diagnose.app", "apps.read", _diagnose_app),
    "validate.server": BrokerOperation("validate.server", "server.read", _no_args(YunohostAdapter.validate_server)),
    "apps.list": BrokerOperation("apps.list", "apps.read", _apps_list),
    "app.info": BrokerOperation("app.info", "apps.read", _app_info),
    "app.resources": BrokerOperation("app.resources", "apps.read", _app_resources),
    "app.config_get": BrokerOperation("app.config_get", "apps.config.read", _app_config_get),
    "services.status": BrokerOperation("services.status", "services.read", _service_status),
    "domains.list": BrokerOperation("domains.list", "domains.read", _no_args(YunohostAdapter.domains_list)),
    "users.list": BrokerOperation("users.list", "users.read", _no_args(YunohostAdapter.users_list)),
    "backups.list": BrokerOperation("backups.list", "backups.read", _no_args(YunohostAdapter.backups_list)),
    "backups.created_at": BrokerOperation("backups.created_at", "backups.read", _backup_times),
    "system.free_space": BrokerOperation("system.free_space", "server.read", _free_space),
    "operations.list": BrokerOperation("operations.list", "logs.read", _operations_list),
    "operation.status": BrokerOperation("operation.status", "logs.read", _operation_name),
    "operation.logs": BrokerOperation("operation.logs", "logs.read", _operation_logs),
    "domain.certificate_info": BrokerOperation("domain.certificate_info", "domains.read", _domain_name),
    "user.groups": BrokerOperation("user.groups", "users.read", _no_args(YunohostAdapter.user_group_list)),
    "user.permissions": BrokerOperation("user.permissions", "users.read", _no_args(YunohostAdapter.user_permission_list)),
    "service.logs": BrokerOperation("service.logs", "logs.read", _service_logs),
    "updates.check": BrokerOperation("updates.check", "system.update", _updates_check),
    "updates.refresh": BrokerOperation("updates.refresh", "system.update", _updates_refresh),
    "migrations.list": BrokerOperation("migrations.list", "system.update", _migrations_list),
    "migrations.state": BrokerOperation("migrations.state", "system.update", _no_args(YunohostAdapter.migrations_state)),
    "firewall.list": BrokerOperation("firewall.list", "firewall.read", _firewall_list),
    "firewall.is_open": BrokerOperation("firewall.is_open", "firewall.read", _firewall_is_open),
    "service.restart": BrokerOperation("service.restart", "services.restart", _service_restart),
    "backup.create": BrokerOperation("backup.create", "backups.create", _backup_create),
    "app.install": BrokerOperation("app.install", "apps.install", _app_install),
    "app.upgrade": BrokerOperation("app.upgrade", "apps.upgrade", _app_upgrade),
    "app.remove": BrokerOperation("app.remove", "apps.remove", _app_remove),
    "app.change_url": BrokerOperation("app.change_url", "apps.upgrade", _app_change_url),
    "app.config_set": BrokerOperation("app.config_set", "apps.config.write", _app_config_set),
    "backup.restore": BrokerOperation("backup.restore", "backups.restore", _backup_restore),
    "system.upgrade": BrokerOperation("system.upgrade", "system.upgrade", _system_upgrade),
    "migrations.run": BrokerOperation("migrations.run", "system.migrate", _migrations_run),
    "firewall.open": BrokerOperation("firewall.open", "firewall.write", _firewall_open),
    "firewall.close": BrokerOperation("firewall.close", "firewall.write", _firewall_close),
    "firewall.reload": BrokerOperation("firewall.reload", "firewall.write", _firewall_reload),
    "user.create": BrokerOperation("user.create", "users.write", _user_create),
    "user.update": BrokerOperation("user.update", "users.write", _user_update),
    "user.delete": BrokerOperation("user.delete", "users.delete", _user_delete),
    "user.group_create": BrokerOperation("user.group_create", "users.write", _group_create),
    "user.group_update": BrokerOperation("user.group_update", "users.write", _group_update),
    "user.group_delete": BrokerOperation("user.group_delete", "users.delete", _group_delete),
    "user.permission_add": BrokerOperation("user.permission_add", "users.write", _permission_add),
    "user.permission_remove": BrokerOperation("user.permission_remove", "users.write", _permission_remove),
    "domain.add": BrokerOperation("domain.add", "domains.write", _domain_add),
    "domain.cert_install": BrokerOperation("domain.cert_install", "domains.write", _domain_cert_install),
}
