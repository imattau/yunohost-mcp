# YunoHost MCP Server Plan

## 1. Goal

Build a secure MCP server for YunoHost that allows AI clients such as Codex, Claude, OpenCode and ChatGPT-compatible MCP clients to inspect, diagnose and administer a YunoHost server through typed, policy-controlled tools.

Core principles:

- use YunoHost's existing administration primitives rather than shell automation
- use Nostr keys for cryptographic identity and signed requests
- treat authentication and authorisation as separate layers
- make read access broad and write access constrained
- never expose arbitrary shell execution
- make every write auditable and traceable to a YunoHost operation
- support both server administration and _ynh package development

---

## 2. Proposed architecture

```
AI / MCP Client
      │
      │ HTTPS + NIP-98 signed request
      ▼
Reverse Proxy
      │
      │ TLS / rate limits / optional IP rules
      ▼
yunohost-mcp
 ┌───────────────────────────────┐
 │ Authentication                │
 │ Nostr signature verification  │
 │ replay protection             │
 ├───────────────────────────────┤
 │ Authorisation                 │
 │ pubkey → role/scopes          │
 │ delegations / expiry          │
 ├───────────────────────────────┤
 │ Safety policy                 │
 │ confirmation / prerequisites  │
 │ operation locks               │
 ├───────────────────────────────┤
 │ MCP tools + resources         │
 ├───────────────────────────────┤
 │ Audit / secret redaction      │
 ├───────────────────────────────┤
 │ YunoHost adapter               │
 │ API / Moulinette / CLI        │
 └───────────────┬───────────────┘
                 ▼
              YunoHost
```

The MCP daemon should run locally on the YunoHost machine. Only its deliberately constrained HTTP endpoint needs to be remotely accessible.

---

## Phase 0: technical investigation

Before implementation, map the current YunoHost administration interfaces.

Identify for each desired operation:

- YunoHost Python/API method
- Moulinette action
- CLI equivalent
- operation logger behaviour
- permissions required
- whether operation is synchronous/asynchronous

Pay particular attention to:

- app lifecycle
- diagnosis
- services
- domains
- certificates
- users
- backups
- update/upgrade
- operation logs
- app manifests/resources
- packaging test infrastructure

The implementation should call native YunoHost Python/API functionality where practical rather than spawning `yunohost ...` commands everywhere.

CLI calls should be an adapter of last resort.

---

## Phase 1: MCP foundation

Build a minimal Python MCP server.

Suggested structure:

```
yunohost-mcp/
├── pyproject.toml
├── src/yunohost_mcp/
│   ├── server.py
│   ├── config.py
│   │
│   ├── auth/
│   │   ├── nostr.py
│   │   ├── nip98.py
│   │   ├── replay.py
│   │   └── identity.py
│   │
│   ├── policy/
│   │   ├── scopes.py
│   │   ├── roles.py
│   │   ├── confirmation.py
│   │   └── locks.py
│   │
│   ├── yunohost/
│   │   ├── adapter.py
│   │   ├── apps.py
│   │   ├── diagnosis.py
│   │   ├── services.py
│   │   └── operations.py
│   │
│   ├── tools/
│   ├── resources/
│   ├── audit/
│   └── models/
└── tests/
```

Start with Streamable HTTP for remote MCP and optionally stdio for local development.

---

## Phase 2: Nostr authentication

Use NIP-98 signed HTTP requests as the native authentication mechanism.

A request should prove:

- pubkey owns the private key
- signature is valid
- request URL matches
- HTTP method matches
- body hash matches where applicable
- timestamp is recent
- event has not already been used

Do not depend on a Nostr relay to verify authentication.

Verification must happen locally.

### Replay protection

Maintain a short-lived cache of used event IDs:

```
event_id → expiry
```

Reject:

- duplicate event IDs
- timestamps outside the permitted clock skew
- malformed events
- invalid signatures
- request/body mismatches

Allow clock-skew tolerance but keep it small.

---

## Phase 3: identity and authorisation

A valid Nostr signature establishes identity only.

It must not imply authority.

Map Nostr pubkeys to roles/scopes.

Example:

```toml
[identity."npub1..."]
name = "Codex development agent"
roles = ["package-developer"]
expires = "2026-12-31T00:00:00Z"
```

Roles could initially be:

- readonly
- operator
- app-admin
- package-developer
- administrator

Scopes should remain the underlying security primitive:

```
server.read

diagnosis.read

apps.read
apps.install
apps.upgrade
apps.remove

services.read
services.restart

logs.read

backups.read
backups.create
backups.restore
backups.delete

users.read
users.write
users.delete

domains.read
domains.write

system.update
system.upgrade

packages.inspect
packages.test
```

Roles merely group scopes.

---

## Phase 4: read-only MVP

The first usable release should be deliberately safe.

Implement:

```
server_info()
health_check()

apps_list()
app_info(app)
app_resources(app)

diagnosis_run()
diagnosis_get()

services_list()
service_status(service)
service_logs(service)
service_history(services)

journal_query(units, ...)
web_logs(...)
system_snapshot()
network_snapshot()
ssh_diagnose()
http_probe(url)
incident_snapshot(...)

domains_list()

users_list()

backups_list()

operations_list()
operation_status(id)
operation_logs(id)

updates_check()
```

Resources could include:

```
yunohost://server
yunohost://diagnosis
yunohost://apps
yunohost://apps/{app}
yunohost://services
yunohost://operations
```

This alone would allow an AI to answer:

- What's wrong with this server?
- Why is Nextcloud unavailable?
- Which apps need updates?
- What is consuming disk space?
- Are there failed YunoHost operations?
- Which HTTP requests returned 500, and which upstream failed?
- Did a service restart, reboot, OOM event, SSH ban, or firewall change coincide?

without giving it write access.

---

## Phase 5: controlled operational tools

Add low-risk writes next:

```
service_restart(service)

backup_create(...)

app_install(...)
app_upgrade(...)

cert_install(domain)

diagnosis_repair(...)
```

Every operation must:

1. validate arguments
2. check permissions
3. check policy
4. acquire an appropriate lock
5. record the initiating Nostr pubkey
6. invoke YunoHost
7. capture the YunoHost operation ID
8. return structured status
9. write an audit entry

Do not make long-running operations depend on a single long HTTP request.

Prefer:

```
app_upgrade()
    ↓
operation_id

operation_status(operation_id)

operation_logs(operation_id)
```

---

## Phase 6: safety policy engine

This is one of the most important parts of the project.

Allow deterministic policies such as:

```toml
[policy.apps.upgrade]
require_backup = true
minimum_free_space = "2GB"

[policy.apps.remove]
require_confirmation = true
require_backup = true
max_backup_age = "24h"

[policy.backups.restore]
require_confirmation = true

[policy.backups.delete]
require_confirmation = true
require_owner_signature = true

[policy.system.upgrade]
require_confirmation = true
```

The AI should not decide whether safeguards apply.

The server does.

### Confirmation model

A destructive operation should initially return:

```
confirmation_required
operation_plan
confirmation_id
expires_at
```

A subsequent signed request performs:

```
confirm_operation(confirmation_id)
```

Do not accept vague confirmation strings such as "yes".

Bind confirmation to:

- requesting pubkey
- exact operation
- arguments
- expiry
- server identity

---

## Phase 7: dry-run and planning

Where YunoHost permits it, expose planning separately from execution.

For example:

```
plan_app_upgrade("nextcloud")
```

could return:

```
app: nextcloud
current_version: ...
target_version: ...
backup_required: true
estimated_backup_size: ...
free_space: ...
warnings: []
blocked: false
```

Then:

```
execute_plan(plan_id)
```

This provides a clean AI workflow:

```
inspect
→ plan
→ reason
→ execute
→ validate
```

---

## Phase 8: package-development MCP

This should probably become the second major feature set.

Expose tooling specifically for _ynh package development:

```
package_inspect(source)
package_lint(source)

package_install_test(source)
package_upgrade_test(source)

package_backup_test(app)
package_restore_test(app)

package_change_url_test(app)
package_remove_test(app)

package_run_tests(source)

package_logs(operation)
```

Package-test backups use unique archive names and are retained for inspection;
deleting one is a separate owner-approved `backup_delete(name)` operation.

The AI-coding workflow then becomes:

```
Codex edits example_ynh
        ↓
package_install_test()
        ↓
failure
        ↓
operation_logs()
        ↓
Codex modifies package
        ↓
package_install_test()
```

That removes the human copy/paste loop.

### Important

Support modern YunoHost packaging semantics.

The coder should not implement legacy assumptions such as manually managing resources that current `manifest.toml` resource definitions handle.

The MCP should expose package resource declarations so an agent can reason about:

- system user
- install directory
- data directory
- permissions
- ports
- apt dependencies
- databases
- sources
- architecture requirements

---

## Phase 9: secret handling

No MCP tool should casually expose YunoHost secrets.

Implement central response filtering.

Redact fields matching known sensitive classes:

```
password
secret
token
private_key
api_key
db_password
ldap_password
session
cookie
```

Logs need filtering too.

Avoid returning full environment files or config files unless specifically designed and permissioned.

Private Nostr keys must never be stored by yunohost-mcp.

---

## Phase 10: audit system

Each request should produce something like:

```
audit_id: mcp-01J...
timestamp: ...
server: npub1server...
caller: npub1agent...
tool: apps.upgrade
arguments:
  app: nextcloud
decision: allowed
yunohost_operation: ...
result: success
```

Store:

- authentication identity
- requested operation
- authorisation decision
- policy decision
- confirmation information
- YunoHost operation ID
- final result

Do not record secrets.

Provide:

```
audit_list()
audit_get(id)
```

as administrator-only MCP tools.

---

## Phase 11: Nostr delegation

Once basic authentication is stable, add signed capability delegation.

Conceptually:

```
Owner key
   │
   │ signs delegation
   ▼
Agent pubkey

scope:
  apps.read
  apps.install
  packages.test

server:
  npub1server...

expiry:
  2026-09-04
```

The delegated identity can then authenticate directly.

Important constraints:

- delegation must specify server
- delegation must expire
- delegation cannot grant permissions the signer lacks
- delegations should be independently revocable

This means an AI can receive a disposable identity without ever possessing the owner's private key.

---

## Phase 12: server Nostr identity

Generate a dedicated server keypair during setup.

```
YunoHost MCP Server
npub1server...
```

Use it for:

- signed operation receipts
- signed health reports
- server discovery
- audit verification
- delegation targeting

The server's private key should be stored with strict filesystem permissions and should not be YunoHost's root/admin credential.

---

## Phase 13: stronger approval model

For high-risk actions, optionally support owner co-signing.

Example:

```
Agent requests:
system_upgrade()

agent signature ✓

policy:
owner_signature_required

        ↓

owner signs approval

        ↓

yunohost-mcp verifies both

        ↓

execute
```

Potential candidates:

- system upgrade
- backup restore
- app removal with data
- user deletion
- domain removal
- firewall changes
- permission changes

This could later work with a Nostr remote signer rather than requiring the owner's private key on the AI machine.

**Status (v1, `solo` profile):** implemented. A single configured owner (`auth/owner.py`) approves via a NIP-98-signed `approve_operation` call, checked against `ConfirmationStore`'s `operation_hash`-bound ticket (`policy/confirmation.py`); `approval_get`/`approval_status` (server.py) expose the authoritative pending record; `yunohost-mcp-approve` (`approve.py`) is the NIP-46 remote-signer client - the owner's private key never touches this AI machine or the MCP server, only the paired remote signer app. An optional, non-authoritative NIP-17 notification (`notify.py`) can nudge the owner when one is pending. `household`/`team`/`strict` multi-owner profiles are deliberately deferred past v1 - see the packaging repo's `docs/owner-approval-plan.md` for the full design and what's still out of scope.

---

## Phase 14: high-level agent workflows

Once primitives are reliable, expose higher-level tools.

For example:

```
diagnose_app(app)

validate_server()

safe_upgrade(app)

repair_app(app, strategy="conservative")

test_package(source)
```

`safe_upgrade()` might internally perform:

```
check diagnosis
→ inspect disk
→ inspect app
→ create backup
→ upgrade
→ check service
→ test HTTP endpoint
→ rerun diagnosis
→ return report
```

These workflows should still run through the same policy engine.

---

## Phase 15: remote deployment

Package yunohost-mcp itself as a YunoHost app.

Installation could ask:

```
MCP domain:
mcp.example.com

Generate server Nostr identity:
yes

Remote MCP enabled:
yes

Initial authorised npub:
npub1...

Initial role:
administrator
```

Resources might include:

- system user
- Python virtualenv
- systemd service
- domain/path
- nginx reverse proxy
- persistent data directory

The service itself should run unprivileged wherever possible.

Any privileged YunoHost interaction should go through a narrowly controlled mechanism rather than simply running the entire HTTP daemon as root.

This deserves a dedicated security design review.

---

## Phase 16: external exposure protections

For an internet-facing endpoint:

- HTTPS only
- NIP-98 authentication
- replay protection
- request size limits
- rate limits
- configurable IP allow/deny lists
- no anonymous MCP discovery containing sensitive information
- bounded log/result sizes
- timeout protection
- concurrency limits
- operation locking
- strong parsing and schema validation

Optional additional modes:

- Nostr auth
- Nostr auth + IP restrictions
- Nostr auth + mTLS
- Nostr auth over Tailscale/WireGuard

---

## Phase 17: fleet support

Do this later, but design identifiers so it remains possible.

An agent could eventually work across multiple servers:

- Which servers have failed diagnosis checks?
- Upgrade Blossom everywhere it is installed.
- Which machines still have expired certificates?
- Run package X against YunoHost versions A, B and C.

Nostr server identities make this particularly clean.

```
npub server A
npub server B
npub server C
```

Delegations can explicitly target individual server identities.

---

## Suggested v0.1 scope

Keep the first release narrow:

- NIP-98 authentication
- pubkey → role/scopes
- replay protection

```
server_info
health_check

apps_list
app_info
app_resources

diagnosis_run
diagnosis_get

services_list
service_status

operations_list
operation_status
operation_logs

updates_check
```

- audit logging
- secret redaction

No destructive writes yet.

That gives us enough to prove:

1. MCP integration works.
2. Nostr authentication works.
3. YunoHost introspection works.
4. AI agents can meaningfully diagnose a server.
5. The permission/audit architecture works.

---

## v0.2

Add:

```
service_restart
backup_create
app_install
app_upgrade
```

plus:

- policy engine
- operation locking
- dry-run/planning
- confirmation infrastructure

---

## v0.3

Make package development first-class:

```
package_inspect
package_install_test
package_upgrade_test
package_backup_test
package_restore_test
package_change_url_test
package_remove_test
```

At this point the project becomes immediately useful for developing the growing number of _ynh packages.

---

## v0.4

Add:

- signed delegations
- temporary agent identities
- server Nostr identity
- signed operation receipts
- owner co-signing

---

## Things the AI coder should explicitly avoid

- Do not expose `shell_exec()` or equivalent.
- Do not make the HTTP service run as root unless there is no viable alternative.
- Do not treat possession of a valid Nostr key as authorisation.
- Do not require Nostr relays for authentication.
- Do not store users' nsec keys.
- Do not pass YunoHost secrets through MCP responses.
- Do not implement package operations based on obsolete YunoHost helper assumptions.
- Do not duplicate YunoHost's own package/resource management where its API already provides it.
- Do not implement long-running operations as indefinitely blocking MCP requests.
- Do not allow concurrent conflicting operations.
- Do not make confirmations purely conversational. They must be cryptographically bound to an exact operation.

---

## Initial definition of success

A strong first demonstration would be:

```
Codex connects remotely to a YunoHost server
        ↓
authenticates using its own Nostr key
        ↓
asks:
"Why is Shakespeare unhealthy?"
        ↓
MCP retrieves:
server information
app information
resources
service state
diagnosis
relevant YunoHost operation logs
        ↓
Codex identifies the likely problem
```

Then v0.2:

```
"Fix it."

        ↓
MCP determines permitted remediation
        ↓
performs only authorised operations
        ↓
records the Codex npub + YunoHost operation
        ↓
reruns health checks
        ↓
returns verified result
```

That is a good boundary for the project: not giving an AI root access, but giving it a secure, cryptographically authenticated YunoHost administration interface with deterministic limits.

# Phase 18 — optional Concord/Armada package announcements (in progress)

Catalogue publication remains the authoritative operation.  After a
successful publication, the package-developer-scoped agent may prepare an
optional announcement for the Armada channel whose name matches the source
repository (for example, `ditto_ynh`).  Channel discovery and exact matching
are isolated from publication, and drafts carry a deterministic idempotency
key so a later Concord writer can retry without duplicate posts.

Still to implement: authenticated Concord community/channel discovery,
agent-bot membership/invite handling, CORD-01/02 encrypted message writing,
and a non-blocking delivery status or retry tool. Configuration now reserves
file-backed bot-key and community-invite paths, with the integration disabled
by default. The credential boundary rejects symlinks and group/world-readable
files before a future protocol adapter can use either secret. The first
CORD-02 HKDF/group-key primitive is now covered locally; event envelopes and
relay transport remain separate. A local CORD-01 envelope builder now covers
the unsigned rumor, signed seal, and stream-signed wrap, with encryption
injected until the NIP-44 conversation-key adapter is finalized. A local
NIP-44 v2 self-conversation adapter is now available. A bounded, injectable
relay publisher now accepts only a completed signed event; community-state
acquisition and post-publish verification remain separate. Its read-side
counterpart now fetches a bounded batch of Control Plane kind-1059 wraps by
derived stream address, without decrypting or trusting them yet.
Control Plane decoding now verifies the outer wrap, actor-signed plaintext
seal, rumor binding, and rumor ID before the channel metadata fold sees it;
the fold now accepts an explicit CORD-04 authorization predicate, but the
roster evaluator itself remains outstanding.
The shareable invite parser now keeps the public naddr separate from the
opaque secret fragment; CORD-05 fragment decoding and bundle validation remain
outstanding. Fragment v4 decoding now handles the stock relay dictionary and
bounded custom relay entries. Bundle validation now checks the self-certifying
community identity and bounds hostile channel/relay allocations; bundle
decryption now derives the CORD-05 token key and validates the plaintext;
public invite-event verification now checks the kind, coordinate, signer, and
revocation marker; relay event lookup and bot join acceptance remain
outstanding. The read transport now fetches the bounded kind-33301 empty-`d`
coordinate for a link signer, and strict NIP-19 decoding now derives that
signer from the invite naddr.
The explicit Guestbook join envelope is now constructible from a validated
bundle, but invite loading still does not publish it automatically; an
acceptance gate and post-join verification are still required.
Protected bot-key loading is now available as a local credential primitive;
the MCP acceptance gate, join publication, and post-join verification remain
unimplemented.
The optional announcement workflow now routes a validated package publication
to the folded channel, derives its public/private channel key, builds the
encrypted chat envelope, and delegates the signed wrap to the bounded relay
publisher. MCP wiring and delivery persistence remain outstanding.
The Control Plane reader now composes bounded relay lookup, derived read-key
decryption, and envelope validation into a local helper; roster authorization
and MCP integration remain outstanding.
The first MCP integration slice is now a separate `catalog_announce` tool,
gated by `communications.armada.write` and therefore available to the
package-developer role. It consumes a prior catalogue publication response,
keeps Armada disabled by default, and returns a non-blocking disabled or
routing status. Its network path still requires a bot that has already joined
the community; automatic invite acceptance, CORD-04 authorization, and
delivery persistence remain future work.
CORD-04 roster authorization is now implemented for this path: owner-rooted
Role and Grant heads are folded with bounded convergence, non-owner edits must
carry an exact current `vac` citation, and Channel metadata requires the
resolved `MANAGE_CHANNELS` permission. Unresolved or unauthorized metadata is
dropped before repository-to-channel routing.
An explicit `armada_join` MCP tool now accepts the configured invite by
publishing the bot's self-signed Guestbook Join, without changing roles or
triggering an announcement. It now performs bounded best-effort Guestbook
lookup and reports whether the exact Join wrap was observed; a relay timeout
therefore yields `published_unverified` rather than a false membership claim.
Guestbook Join/Leave decoding and state folding are now implemented with
signature/seal binding checks, millisecond ordering, deterministic tie-breaks,
and future-time rejection. Full Kick/Ban/snapshot handling remains separate
follow-up work. Authorized kind-3309 Kick folding is now supported through an
explicit CORD-04 predicate; unverified kicks remain ignored. Banlist and
epoch-snapshot inputs are now supported through explicit authorization and
bounded filtering parameters; wiring the folded Control Plane banlist and
refounder authority into the live membership reader remains follow-up work.
The configured Armada timeout is now propagated through invite lookup, Control
Plane lookup, Guestbook Join verification, and announcement/Join publishing,
so every network leg remains bounded by the deployment setting.
Invite bundle validation now also rejects expired bundles, non-ws(s) relay
URLs, and duplicate channel IDs before any membership or announcement action.
Successful announcement event IDs are now persisted in a small SQLite delivery
store keyed by the deterministic draft idempotency key; repeated requests
return `already_published` instead of reposting. Failed or unroutable
announcements are not recorded as delivered.
The scoped `catalog_announcement_status` tool now exposes persisted delivery
state by idempotency key, allowing an agent to inspect delivery before retrying
without posting another event.
An opt-in `armada_auto_announce` setting now lets `catalog_publish` invoke the
same best-effort announcement path after a successful catalogue result and
attach its status; announcement exceptions are isolated so they cannot turn a
successful catalogue publication into a failure. The default remains false.
