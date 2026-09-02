# Phase 0 Investigation: YunoHost Administration Interfaces

Source: `/tmp/yunohost-src` (clone of `github.com/YunoHost/yunohost`, branch `dev`, commit `3c339cc3` 2026-08-23). `/tmp/yunohost-core` is the same repo/commit — only `src/utils/app_utils.py` and git-internal files differ, not meaningfully. All references below are against `yunohost-src`.

## How the system is put together

- **`src/*.py`** are plain Python modules (`app.py`, `diagnosis.py`, `service.py`, `log.py`, ...) exposing plain functions (`app_list`, `diagnosis_run`, `service_status`, `log_list`, ...). No decorators — they're just called by the framework.
- **`share/actionsmap.yml`** (2415 lines) is the single source of truth for the CLI *and* the REST API surface. Top-level keys (`user`, `domain`, `app`, `backup`, `service`, `firewall`, `dyndns`, `tools`, `hook`, `log`, `diagnosis`, `storage`, `settings`) map to modules; each `actions:` entry maps a subcommand (e.g. `tools: rootpw`) to a function name by convention (`tools_rootpw`) and optionally declares `api: METHOD /path` for REST exposure. Not every CLI action has an `api:` line — some are CLI-only.
- **Moulinette** (`github.com/yunohost/moulinette`, separate pip package, not vendored, not installed in this sandbox) is the framework that parses `actionsmap.yml`, dispatches to these functions, handles CLI/API interfaces, locking, i18n, and auth. YunoHost itself does not reinvent dispatch.
- **`bin/yunohost`** is the CLI entrypoint: requires `os.geteuid() == 0` (hard root check) before doing anything, then calls `moulinette.cli(args, actionsmap="/usr/share/yunohost/actionsmap.yml", ...)`.
- **There is already a REST API**: `src/__init__.py:api()` calls `moulinette.api(host, port, actionsmap=..., routes={("GET","/installed"): is_installed_api}, allowed_cors_origins=...)`. This is the existing `yunohost-api` systemd service (bottle-based, typically bound to `127.0.0.1:6787`), auto-generated from the *same* actionsmap. Auth is via `src/authenticators/ldap_admin.py` (`Authenticator` class) — LDAP-bound admin session cookie — or `ldap_ynhuser.py` for the portal API (regular user auth, different actionsmap: `actionsmap-portal.yml`).

This matters a lot for adapter strategy — see Conclusions.

---

## v0.1 read operations

### `server_info` → `tools_versions()`
`src/tools.py:61` — `def tools_versions() -> dict[str, dict[str, str]]`. Returns installed package versions (yunohost, moulinette, ssowat, etc.) with version/repo/commit info. Sync, no operation log. `actionsmap.yml` → `tools: versions`. No write, no special permission beyond normal API auth.

No single "server_info" call exists; likely composite of `tools_versions()` + `domain_list()` (main domain) + disk/`disk.py` helpers. Worth building a composed `server_info()` MCP tool rather than expecting one YunoHost call.

### `health_check` → no native equivalent; closest is `diagnosis_show()`
There is no single "health check" function. `diagnosis_show()` (`src/diagnosis.py:71`) aggregates all diagnosis categories into a summary — this is the closest native primitive and should back `health_check()`.

### `apps_list` → `app_list(full: bool = False)`
`src/app.py:130` — `def app_list(full: bool = False) -> dict[Literal["apps"], list[AppInfo]]`. Sync, reads from `/etc/yunohost/apps/*/settings.yml` + manifest cache, no operation log. `actionsmap.yml` → `app: list`, exposed as `api: GET /apps`.

### `app_info` → `app_info(app, full=False, ...)`
`src/app.py:147` — signature `def app_info(app: str, full: bool = False, ...)`. Returns dict with manifest, settings, permissions, upgradability. Sync, no op log. `api: GET /apps/{app}`.

### `app_resources` → manifest resource introspection
No dedicated `app_resources()` call; resources are computed by `AppResourceManager` (`src/utils/resources.py:41`) from the app's `manifest.toml`. `app_info(app, full=True)` likely surfaces enough; otherwise the MCP adapter can instantiate `AppResourceManager` directly against a manifest to list declared resources (system user, install dir, data dir, ports, apt deps, database, sources — see resource classes below).

### `diagnosis_run` / `diagnosis_get`
`src/diagnosis.py`:
- `diagnosis_list()` (`:46`) — lists available diagnosis categories.
- `diagnosis_get(category, item)` (`:50`) — fetch one diagnosis item.
- `diagnosis_show(...)` (`:71`) — full aggregated report (this is what CLI `yunohost diagnosis show` calls).
- `diagnosis_run(...)` (`:159`) — **triggers** diagnosis (writes cache under `/var/cache/yunohost/diagnosis/`), can take real time (network checks, port scans etc.) — should be treated as a long-running op in the MCP, not assumed instant.

Diagnosers live in `src/diagnosers/` as numbered plugin modules (e.g. `50-systemresources.py`) auto-discovered — useful to enumerate for documenting what "categories" exist (ip, dns, ports, web, mail, system resources, apps, services, security, ...).

### `services_list` / `service_status`
`src/service.py`:
- `service_status(names=[])` (`:349`) — status of one/several/all services (systemd wrapper + custom service registrations). Sync.
- No separate `service_list`; `service_status([])` with empty list returns all. Confirm via CLI help but this is the pattern used elsewhere in the codebase.
- Writes: `service_start/stop/restart/reload/enable/disable` (`:154,182,234,208,312,331`) — these are the v0.2 write targets.

### `domains_list` → `domain_list(...)`
`src/domain.py:155` — `def domain_list(...)`. Sync, no op log, reads `/etc/yunohost/domains.yml` + queries DNS state.

### `users_list` → `user_list(fields: list[str] | None = None)`
`src/user.py:79` — `def user_list(fields=None) -> dict[str, dict[str, Any]]`. Sync, queries LDAP directly (via moulinette LDAP interface) — **note this requires a working LDAP connection/auth context**, not just filesystem reads.

### `backups_list` → `backup_list(with_info=False, human_readable=False)`
`src/backup.py:2293`. Sync, lists archives under `/home/yunohost.backup/archives/`.

### `operations_list` / `operation_status` / `operation_logs` → `log_list` / `log_show` + `OperationLogger`
`src/log.py`:
- `log_list(limit=None, with_details=False, with_suboperations=False, since_days_ago=30)` (`:139`) — lists operation log entries by scanning `OPERATIONS_PATH` (`.yml` metadata + `.log` files), builds parent/child tree for suboperations, returns `{"operation": [...]}`. Each entry: `name` (the operation id, e.g. `20260201-120000-app_install`), `path`, `description`, `success` (True/False/"?"), `started_at`, optionally `started_by`, `parent`.
- `log_show(...)` (`:267`) — reads full log content/metadata for one operation id — this backs `operation_logs(id)`.
- **`OperationLogger`** (`:595`) is the class every write operation instantiates to produce these logs. Key behavior:
  - Operation id = timestamp + operation name (filename-derived), auto-generated, not caller-supplied.
  - Supports **parent/child nesting**: if a lock file `/var/run/moulinette_yunohost.lock` exists and another operation is in-flight, a new `OperationLogger` auto-detects it's a sub-operation of the running one (via matching open file handles across the process tree). This means operations triggered "inside" other operations (e.g. permission init during app install) get nested — important for building a clean `operations_list()` view.
  - `self.data_to_redact` seeds from `/etc/yunohost/mysql` and `/etc/yunohost/psql` (DB root passwords) — confirms **the platform itself does secret redaction in its own logs**; the MCP's own redaction (Phase 9) should be a second, independent layer, not a replacement.
  - `started_by`: resolved from the LDAP admin session cookie if interface is `"api"`, else guessed from the parent process (cli case). **This means "who ran this" is only reliably known through YunoHost's own auth context** — the MCP adapter must pass/attribute its own identity some other way (e.g. its own audit log, since it won't be logging in via LDAP as different users).

This is the operation-id abstraction Phase 5/10 of PLAN.md wants — it already exists natively, no need to invent one.

### `updates_check` → `tools_update(...)` / `tools_update_norefresh()`
`src/tools.py:354,359`. `tools_update_norefresh()` returns `AvailableUpdatesInfos` from cache without hitting the network; `tools_update(...)` (`:359`) refreshes apt/app catalogs first — the latter is a real (network) operation and should be modeled as such, not instant. Upgrade itself is `tools_upgrade(operation_logger, target=None)` (`:535`) — **note it explicitly takes an `operation_logger` parameter**, i.e. many "core" functions expect the caller (moulinette dispatch) to have already constructed one and pass it in — direct in-process calls to write functions must replicate this, not just call the bare function.

---

## v0.2 write operations (lower detail, for later phases)

- `service_restart(names)` — `src/service.py:234`.
- `backup_create` — not directly seen in the grep above but present in `backup.py` (pattern consistent with `backup_list`); needs a follow-up grep when implementing.
- `app_install` / `app_upgrade` — in `app.py`, both take `operation_logger` params like `tools_upgrade`, dispatch through `AppResourceManager` for provisioning, and are genuinely long-running (apt installs, git clones, DB migrations). These are prime candidates for the async operation_id pattern from PLAN.md Phase 5.
- `tools_shutdown` / `tools_reboot` (`tools.py:658,677`) — both take `operation_logger` and a `force` flag — high-risk, map to Phase 13 co-signing candidates alongside system upgrade.

---

## Permission model — `permission.py`

Three functions only: `permission_create` (`:380`), `permission_url` (`:460`), `permission_delete` (`:581`). This is YunoHost's *app-facing* ACL system (which users/groups can access which app URLs) — it is **not** a general RBAC system for YunoHost administration itself, and it's irrelevant to gating admin API calls. It governs SSOwat access control for app permissions (`mail`, `admin` special groups etc.).

**Implication for MCP**: YunoHost has no notion of "this API caller may only read, not write" — that's enforced entirely by *who can authenticate as LDAP admin at all* (full admin) or by app-permission scoping (which is about end-user app access, not administration). **The MCP's own scopes/roles system (Phase 3) is not layering on top of an existing YunoHost RBAC — it is the only RBAC**, since YunoHost's own model is binary (root/admin vs. nothing) for administrative actions. This validates PLAN.md's approach of treating Nostr-pubkey→scope mapping as a wholly separate authorization layer, but means the MCP process itself needs privileged (root or LDAP-admin) access to do anything — there's no narrower native credential to delegate.

---

## App resource system (`src/utils/resources.py`) — for Phase 8

`AppResourceManager` (`:41`) orchestrates a list of `AppResource` (`:143`) subclasses driven by an app's `manifest.toml` `[resources]` table. Concrete resource types found:

| Class | Line | Purpose |
|---|---|---|
| `SourcesResource` | 319 | upstream tarball/git sources, checksums |
| `PermissionsResource` | 561 | SSOwat permission/URL wiring |
| `SystemuserAppResource` | 775 | dedicated system user |
| `InstalldirAppResource` | 927 | install directory |
| `DatadirAppResource` | 1047 | persistent data directory |
| `AptDependenciesAppResource` | 1167 | apt package deps |
| `PortsResource` | 1314 | port allocation |
| `DatabaseAppResource` | 1478 | MySQL/PostgreSQL provisioning |
| `NodejsAppResource` | 1616 | Node.js runtime pinning |
| `RubyAppResource` | 1716 | Ruby runtime pinning |
| `GoAppResource` | 1846 | Go runtime pinning |
| `ComposerAppResource` | 1956 | PHP Composer deps |

This confirms PLAN.md Phase 8's list (system user, install dir, data dir, ports, apt deps, database) maps 1:1 to real classes — `package_resources`-style tooling should introspect `AppResourceManager` against a candidate `manifest.toml`, not hand-roll parsing.

---

## Phase 0 conclusions

**Recommended adapter strategy: run yunohost-mcp as a privileged local process that imports `yunohost` modules directly in-process, not by shelling out to `yunohost` CLI and not by proxying the existing `yunohost-api`.**

Reasoning:
1. **CLI subprocess (`yunohost ...`)** works but is slow, loses typed return values (parses stdout text/JSON), and PLAN.md explicitly wants this as "adapter of last resort" — confirmed as the right call. Reserve it for anything with no clean Python entrypoint.
2. **Proxying the existing `yunohost-api`** (bottle server on 6787) sounds attractive but its auth model is LDAP-admin-cookie based — it wants a real admin login (username/password), not a Nostr pubkey, and every request would need a valid session cookie the MCP would have to independently establish and manage. It also doesn't solve the authorization-layering problem (Phase 3) any better than calling Python directly — the API is all-or-nothing admin access either way. Net: it adds an HTTP hop and a credential-juggling problem for no isolation benefit.
3. **Direct in-process import of `src/*.py` functions** is fastest, gives typed returns, and is what YunoHost's own moulinette dispatch does under the hood anyway (it just calls the bare function). The catch: several write functions (`tools_upgrade`, `tools_shutdown`, `app_install`, likely `app_upgrade`) take an `operation_logger` parameter explicitly — the MCP adapter must construct `OperationLogger(operation, ...)` itself, call `.start()`/`.success()`/`.error()` around the call, exactly as moulinette's dispatcher would, or these calls will fail or silently skip logging.

**Risks / surprises to design around:**
- **Root requirement is real and hard-coded** (`bin/yunohost` checks `os.geteuid() == 0`; write functions assume a root-level environment for systemd/apt/LDAP-admin operations). PLAN.md Phase 15's "run unprivileged wherever possible" is aspirational but the *YunoHost-calling* part of the process cannot be unprivileged — mitigate by splitting the MCP into an unprivileged HTTP-facing process (auth, policy, audit) and a minimal privileged helper/socket that only executes pre-validated YunoHost calls, so the attack surface that's actually root-privileged is as small as possible.
- **`user_list` requires a live LDAP context** (not just file reads) — the in-process import approach needs moulinette's LDAP interface initialized, which likely means importing/initializing `moulinette` itself (locale, auth context) before calling into `yunohost.*`, not just `import yunohost.user`.
- **Operation nesting via lock-file/proc-tree inspection** (`OperationLogger.parent_logger`) is somewhat fragile/implicit — worth verifying in Phase 1 prototyping that operations triggered by the MCP process get logged/nested sanely rather than each being misattributed as root operations or breaking the "one lock at a time" assumption baked into `/var/run/moulinette_yunohost.lock`.
- **`diagnosis_run` and `tools_update` are genuinely slow/networked** — confirms PLAN.md Phase 5's insistence on async operation-id patterns rather than blocking HTTP calls; don't wait on these synchronously in an MCP tool handler.
- **No native RBAC to lean on** — the MCP's Phase 3 authorization layer is doing 100% of the access-control work; the underlying YunoHost credential the MCP process uses is inherently "full admin." This raises the stakes on Phase 6 (policy engine) and Phase 9 (secret redaction) since a bug there is a bug in the *only* access control that exists.
- YunoHost's own `OperationLogger` already redacts DB passwords from logs — the MCP's redaction (Phase 9) is an additive second layer, not a replacement; don't assume "no redaction needed because YunoHost logs are already clean."
