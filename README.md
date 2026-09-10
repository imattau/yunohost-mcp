# yunohost-mcp

<!-- mcp-name: io.github.imattau/yunohost-mcp -->

Secure MCP server for YunoHost: Nostr-authenticated, policy-controlled, auditable administration, diagnostics, and `_ynh` package development for AI clients (Codex, Claude, OpenCode, ChatGPT-compatible MCP clients).

See [PLAN.md](PLAN.md) for the full design and phased roadmap, and [PHASE0_INVESTIGATION.md](PHASE0_INVESTIGATION.md) for how it maps onto YunoHost's actual Python API.

## Running the server

```
yunohost-mcp --transport stdio   # local development, fully trusted (no NIP-98 handshake)
yunohost-mcp --transport http --host 127.0.0.1 --port 8765   # NIP-98-authenticated, remote-capable
```

By default `fake_yunohost` is off (real mode) — set `YUNOHOST_MCP_FAKE_YUNOHOST=true` to run against canned data on a machine without YunoHost installed. See `identity.example.toml` for `identity.toml`'s shape (pubkey → role mapping; required before any HTTP request can do anything).

## Optional local Polypack memory

The server can act as an authenticated façade for a separately installed
Polypack MCP service. Set `YUNOHOST_MCP_POLYPACK_URL` to that service's
loopback `/mcp/` endpoint; the URL must resolve to `127.0.0.1`, `::1`, or
`localhost`, and Polypack remains the sole owner of its database. The YunoHost
MCP HTTP endpoint is still the only endpoint agents should expose publicly.

The initial integration exposes bounded `memory_get`, `memory_list_contexts`,
`memory_recall`, `memory_context`, `memory_thread`, `memory_store`, and
`memory_feedback` tools. Memory reads, writes, and feedback have separate
`memory.read`, `memory.write`, and `memory.feedback` scopes; writes are locked
and audited, while content is represented in the audit log only by length and
hash. Provenance is added by this server, and user metadata cannot forge its
reserved `_yunohost_*` fields. The integration is optional and core YunoHost
tools continue to work when Polypack is not installed or not configured.

## Installing the client tools

The recommended client-side path is `uvx`, which creates an isolated
environment for the command without requiring users to manage a Python virtual
environment:

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect --help
```

For a persistent command-line installation, use:

```bash
uv tool install yunohost-mcp-connect
```

The package is also installable with `python3 -m pip install
yunohost-mcp-connect`; that path is mainly useful for development or systems
where `uv` is not available.

## Agent-assisted setup

The setup wizard is designed to be run by an AI agent on the user's local
machine. It generates a fresh client identity, writes the selected MCP client
configuration, and prints the one remaining security-sensitive step: granting
the generated npub an appropriate role on the YunoHost server.

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
  --server https://your-yunohost-domain/mcp \
  --client codex \
  --format json
```

Supported clients are `codex`, `claude-desktop`, `claude-code`, `gemini`,
`hermes`, and `opencode`.
Setup is safe to rerun, refuses conflicting server definitions, backs up an
existing configuration before changing it, and never prints the private key.
Use `--print-only` when the agent should display configuration without writing
it. After granting the npub and restarting the client, diagnose the connection:

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect doctor \
  --server https://your-yunohost-domain/mcp \
  --key-file ~/.config/yunohost-mcp/codex.key \
  --format json
```

## Connecting a client: yunohost-mcp-connect

Mainstream MCP clients (Claude Desktop, a plain Codex install, etc.) have no way to sign a NIP-98 `Authorization` header — that's specific to this server. `yunohost-mcp-connect` bridges the gap: a small local process that speaks plain MCP over stdio to your actual client, and forwards every request to the remote `--transport http` server, signed with your own Nostr key.

```
yunohost-mcp-connect --remote-url https://your-yunohost-domain/mcp --key-file ~/.config/yunohost-mcp/key
```

- `--key-file` (or `$YUNOHOST_MCP_CLIENT_KEY_FILE`) points at a file holding a hex or `nsec1...` private key — preferred over `--key`/`$YUNOHOST_MCP_CLIENT_KEY`, which put the key in argv/environment where other processes on the same machine can read it.
- `--generate-key PATH` writes a fresh private key to `PATH` (0600; refuses to overwrite an existing file), prints its npub, and exits without connecting anywhere — the way to get a `--key-file` in the first place. Use a distinct `PATH` per client; see "Give each client its own key file" below.
- `--delegation-file` (or `$YUNOHOST_MCP_CLIENT_DELEGATION_FILE`) presents a delegation event (PLAN.md Phase 11) alongside your own signature, for a disposable agent identity an owner granted a subset of their access to.
- Point your MCP client's config at this command (not the server directly) — `tools/list`, `tools/call`, `resources/list`, and `resources/read` are forwarded verbatim; authorization, policy, and audit still happen on the remote server.

Each connector starts its local MCP endpoint independently of the remote
YunoHost handshake. If one configured YunoHost instance is offline, that
connector stays alive, reports no discovered tools until the instance returns,
and retries on later requests; other configured MCP servers can still start
and remain usable.

## Incident introspection

The server includes bounded, read-only diagnostics for intermittent outages:

- web_logs parses Nginx access/error logs, including HTTP and upstream status.
- journal_query reads allowlisted service, SSH, firewall, kernel, OOM, and
  systemd journals.
- system_snapshot, service_history, ssh_diagnose, and network_snapshot expose
  host, restart, access-control, and socket state.
- http_probe tests an HTTP(S) endpoint, while incident_snapshot collects the
  main evidence for a time window.

Log paths, output limits, command timeouts, and whether private HTTP targets
are permitted are configurable with YUNOHOST_MCP_* settings. All of these
tools are read-only and enforce bounded output.

## Connecting Claude Desktop or Codex

Both point at `yunohost-mcp-connect`, not at the server directly — the bridge is what signs each request with your Nostr key. Use the full path to `yunohost-mcp-connect` in whatever environment you installed `yunohost-mcp` into (e.g. `~/.local/pipx/venvs/yunohost-mcp/bin/yunohost-mcp-connect`, or a venv's `bin/` directory — `which yunohost-mcp-connect` after activating it will tell you).

**Give each client its own key file.** `YUNOHOST_MCP_CLIENT_KEY_FILE` *is* the identity — whichever key signs a request determines its role and scopes on the server, nothing else. Point two different clients (or two different config files for the same client — a project-local `.codex/config.toml` shadows `~/.codex/config.toml`) at the same key file and the second one silently authenticates as the first, with its exact permissions - no error, nothing to notice. Generate a fresh key per client rather than copying one that already works:

```
yunohost-mcp-connect --generate-key ~/.config/yunohost-mcp/claude-desktop.key
yunohost-mcp-connect --generate-key ~/.config/yunohost-mcp/codex.key
```

Each prints the new key's npub - grant it whatever role is appropriate for that specific client (see "Granting a disposable agent identity access" below, or `identity.toml` directly), not the role you already gave a different one. `--generate-key` refuses to overwrite a file that already exists.

**Claude Desktop** (`claude_desktop_config.json` — Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "yunohost-mcp": {
      "command": "/full/path/to/yunohost-mcp-connect",
      "env": {
        "YUNOHOST_MCP_CLIENT_REMOTE_URL": "https://your-yunohost-domain/mcp",
        "YUNOHOST_MCP_CLIENT_KEY_FILE": "/home/you/.config/yunohost-mcp/claude-desktop.key"
      }
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):

```toml
[mcp_servers.yunohost-mcp]
command = "/full/path/to/yunohost-mcp-connect"

[mcp_servers.yunohost-mcp.env]
YUNOHOST_MCP_CLIENT_REMOTE_URL = "https://your-yunohost-domain/mcp"
YUNOHOST_MCP_CLIENT_KEY_FILE = "/home/you/.config/yunohost-mcp/codex.key"
```

Run `yunohost-mcp-connect --key-file <path>` once per new key to see its npub (`yunohost-mcp-connect: signing as npub1...`), then grant that npub whatever role is actually appropriate for that client in `identity.toml` - not the role you already gave a different one.

For a delegated (disposable) identity instead of your own key, add `YUNOHOST_MCP_CLIENT_DELEGATION_FILE` pointing at the file `yunohost-mcp-delegate` produced (see below). Restart the client after editing its config — both read this file once, at startup.

## Granting a disposable agent identity access: yunohost-mcp-delegate

An `identity.toml` entry grants access to one specific pubkey, permanently (until edited). A delegation (PLAN.md Phase 11) is the other way to grant access: an owner signs a short-lived, scoped grant to an agent's own disposable key, without ever adding that key to `identity.toml` or handing over any private key. `yunohost-mcp-delegate` is what an owner runs to create one:

```
yunohost-mcp-delegate --key-file ~/.config/yunohost-mcp/key \
  --delegate npub1... \
  --remote-url https://your-yunohost-domain/mcp \
  --role readonly --ttl 24h \
  --out agent-delegation.json
```

- `--delegate` is the agent's own pubkey (it must sign its own NIP-98 requests as always — a delegation never replaces that, it only adds standing).
- `--remote-url` fetches the server's pubkey and this owner's own current scopes automatically — no need to type the server's pubkey by hand, and an over-broad `--scope`/`--role` request is flagged (the server can never grant more than the delegator's own current scopes; see `auth/delegation.py`). Pass `--server` instead if you'd rather supply the server's pubkey directly.
- `--scope`/`--role` (repeatable, combinable) choose what to grant; `--ttl` (e.g. `24h`, `7d`) how long — the server rejects anything over 30 days.
- The output is a signed delegation event: a bearer credential once issued. Hand the file to the agent to use with `yunohost-mcp-connect --delegation-file agent-delegation.json`, over a channel you trust (the same as you'd hand over an API key).
- To take a delegation back before it expires, add its `id` (printed after signing) to `revoked_delegations.toml` — this is independent of, and finer-grained than, removing the delegator's own `identity.toml` entry (which revokes every delegation they've ever issued).

## Approving high-risk operations: yunohost-mcp-approve

Some operations (`system_upgrade`, `backup_restore`, `backup_delete`, `system_migrate`, `user_delete`, permission changes, firewall changes) require owner co-signature on top of the requester's own confirmation (PLAN.md Phase 13, `solo` profile - see `docs/owner-approval-plan.md` in the packaging repo for the full design). The requester's call pauses with a `confirmation_id`; the configured owner reviews and approves it with `yunohost-mcp-approve`, signing through their own [NIP-46](https://nips.nostr.com/46) remote signer app (Amber, nsec.app, ...) - their private key never touches this server or the requesting agent's machine.

DNS publishing, catalogue publication, and package-test lifecycle operations also require owner co-signature. Package-test writes must first use `package_test_prepare`; the returned short-lived session binds the operation to one requester, candidate source, and app id. Treat package testing as privileged because candidate package scripts execute with YunoHost privileges.

For reverse-proxy deployments, set `YUNOHOST_MCP_PUBLIC_BASE_URL` to the exact public origin used in NIP-98 signatures (for example `https://mcp.example.org`). Requests with an unexpected `Host` header are rejected. Keep the local stdio transport restricted to trusted local clients: it intentionally grants the local process full administrator scope.

## Optional NostrHost control-plane bridge

On a NostrHost derivative, the reference FastMCP server can submit registered
operations to the local signed control plane instead of executing them in the
MCP process. Enable it with `YUNOHOST_MCP_NATIVE_CONTROL_PLANE_ENABLED=true`,
set `YUNOHOST_MCP_NATIVE_CONTROL_PLANE_RELAY`, and provision a dedicated
64-character hex agent key at
`YUNOHOST_MCP_NATIVE_CONTROL_PLANE_AGENT_KEY_PATH`. The MCP server publishes
the signed request only; the control-plane daemon performs scope checks,
administrator approval, execution, and audit publication.

For bridged calls, the dedicated bridge key is the signed `requester` and
the authenticated MCP caller's Nostr public key is carried as the signed
`actor` tag on the request, execution, result, and state-snapshot records.
This makes agents and human users first-class audit identities while keeping
authorization anchored to the key that cryptographically submitted the
request.

One-time setup, on whatever device the owner keeps their signer app on:

```
yunohost-mcp-approve pair --owner-npub <owner-npub>
```

Prints a `nostrconnect://` URI to open in the signer app. This persists a reconnectable session locally so later approvals don't need to re-pair. If the signer app can instead export a `bunker://` connection string itself (its own "add a connection" feature), `yunohost-mcp-approve pair --owner-npub <owner-npub> --bunker-uri <uri>` connects immediately using that instead - no link to open, nothing to wait on. Pairing requires the explicit owner key so a transport endpoint cannot be substituted for the configured owner.

To review and approve a specific pending operation:

```
yunohost-mcp-approve approve --server https://your-yunohost-domain/mcp --confirmation-id confirm-...
```

This fetches the authoritative pending-operation record from the server (never trusts a locally-supplied plan), displays the exact tool, arguments, and `operation_hash`, and requires typing `yes` before submitting the signed approval. Once approved, the original requester can retry its call.

**Automatic push approval.** Once paired, this step usually isn't needed at all: the moment a `require_owner_signature` operation is requested, the server itself reuses the same paired session to open a live NIP-46 connection and ask your signer app to sign a small, human-readable approval event right then - a real push prompt on your signer app, no command to run. Approving there marks the ticket approved directly; declining, timing out (`YUNOHOST_MCP_OWNER_PUSH_APPROVAL_TIMEOUT_SECONDS`, default 90s), or no session being paired yet just leaves the ticket pending for a manual `yunohost-mcp-approve approve` as above. Disable entirely with `YUNOHOST_MCP_OWNER_PUSH_APPROVAL_ENABLED=false`.

## Optional Armada announcements

The package-developer role includes `communications.armada.write`. With the
Armada integration enabled, `armada_join` explicitly accepts the configured
Concord invite for the bot by publishing a Guestbook Join. After a successful
`catalog_publish`, call `catalog_announce` with its JSON result to post to the
channel whose name matches the package repository (for example,
`ditto_ynh`). `catalog_announcement_status` checks durable delivery state.

Announcements are disabled by default and are best-effort. To enable them,
provide a root-owned, mode-0600 bot key and invite URL file, then set:

```text
YUNOHOST_MCP_ARMADA_ENABLED=true
YUNOHOST_MCP_ARMADA_BOT_KEY_PATH=/etc/yunohost-mcp/armada-bot.key
YUNOHOST_MCP_ARMADA_COMMUNITY_INVITE_PATH=/etc/yunohost-mcp/armada-community.invite
```

Set `YUNOHOST_MCP_ARMADA_AUTO_ANNOUNCE=true` to have `catalog_publish` attempt
the announcement automatically after catalogue success. A failed or
unverified Armada operation never changes the catalogue result. The signing
identity must already have the required channel key; invite acceptance and
role assignment are separate operations.

**Per-agent announcement keys.** By default every announcement signs with
the shared bot key above. An `identity.toml` entry can instead set
`armada_key_path` to a dedicated, root-owned, mode-0600 key file so that
identity's own announcements and `armada_join` calls use its own Concord
identity instead of the shared bot:

```toml
[identity."npub1..."]
name = "release-bot-a"
roles = ["package-developer"]
armada_key_path = "/etc/yunohost-mcp/armada-bot-a.key"
```

That identity must call `armada_join` itself once its key file is in place -
having a distinct key implies nothing about community membership or channel
access. This is still a server-held, file-backed credential like the shared
bot key, never the identity's own NIP-98 signing key.

**Announcing with the agent's own key, no key file at all.** An MCP agent
connected through `yunohost-mcp-connect` (`bridge.py`) already holds its own
Nostr key locally to sign every NIP-98 request - it can announce and join
under that same key, with zero server-side credential provisioning, using
`catalog_announce_draft`/`catalog_announce_submit` and
`armada_join_draft`/`armada_join_submit` instead of the one-shot tools:

1. `catalog_announce_draft(source, catalogue_publication)` (or
   `armada_join_draft()`) does all the routing and channel-key work that
   needs no secret, and returns an unsigned event plus a short-lived
   `draft_id`.
2. The agent signs that exact event locally. The bridge answers this itself
   via a local-only `sign_nostr_event(kind, tags, content, created_at)` tool
   (never forwarded to the remote server, and restricted to Concord seal
   events) - the private key never leaves the bridge process.
3. `catalog_announce_submit(draft_id, signed_event)` (or
   `armada_join_submit`) verifies the signature matches exactly what was
   issued and the identity that requested it, then publishes.

The shared bot key / `armada_key_path` still cover `catalog_publish`'s
`YUNOHOST_MCP_ARMADA_AUTO_ANNOUNCE` hook and any non-interactive/stdio
caller, since neither can do this two-step round trip.

## Development

```
uv sync --group dev
uv run pytest -q
```

## Creating a release tag

Maintainers can run the GitHub Actions **Tag release** workflow manually from
the branch or commit to release, providing a version without the `v` prefix
(for example, `0.1.1`). It validates the version, refuses to overwrite an
existing tag, runs the full CI checks on Python 3.11 and 3.12, and only then
pushes an annotated `v<version>` tag.
