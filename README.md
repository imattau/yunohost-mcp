# yunohost-mcp

Secure MCP server for YunoHost: Nostr-authenticated, policy-controlled, auditable administration, diagnostics, and `_ynh` package development for AI clients (Codex, Claude, OpenCode, ChatGPT-compatible MCP clients).

See [PLAN.md](PLAN.md) for the full design and phased roadmap, and [PHASE0_INVESTIGATION.md](PHASE0_INVESTIGATION.md) for how it maps onto YunoHost's actual Python API.

## Running the server

```
yunohost-mcp --transport stdio   # local development, fully trusted (no NIP-98 handshake)
yunohost-mcp --transport http --host 127.0.0.1 --port 8765   # NIP-98-authenticated, remote-capable
```

By default `fake_yunohost` is off (real mode) — set `YUNOHOST_MCP_FAKE_YUNOHOST=true` to run against canned data on a machine without YunoHost installed. See `identity.example.toml` for `identity.toml`'s shape (pubkey → role mapping; required before any HTTP request can do anything).

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

Supported clients are `codex`, `claude-desktop`, `claude-code`, and `hermes`.
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

Some operations (`system_upgrade`, `backup_restore`, `system_migrate`, `user_delete`, permission changes, firewall changes) require owner co-signature on top of the requester's own confirmation (PLAN.md Phase 13, `solo` profile - see `docs/owner-approval-plan.md` in the packaging repo for the full design). The requester's call pauses with a `confirmation_id`; the configured owner reviews and approves it with `yunohost-mcp-approve`, signing through their own [NIP-46](https://nips.nostr.com/46) remote signer app (Amber, nsec.app, ...) - their private key never touches this server or the requesting agent's machine.

One-time setup, on whatever device the owner keeps their signer app on:

```
yunohost-mcp-approve pair
```

Prints a `nostrconnect://` URI to open in the signer app. This persists a reconnectable session locally so later approvals don't need to re-pair. If the signer app can instead export a `bunker://` connection string itself (its own "add a connection" feature), `yunohost-mcp-approve pair --bunker-uri <uri>` connects immediately using that instead - no link to open, nothing to wait on.

To review and approve a specific pending operation:

```
yunohost-mcp-approve approve --server https://your-yunohost-domain/mcp --confirmation-id confirm-...
```

This fetches the authoritative pending-operation record from the server (never trusts a locally-supplied plan), displays the exact tool, arguments, and `operation_hash`, and requires typing `yes` before submitting the signed approval. Once approved, the original requester can retry its call.

**Automatic push approval.** Once paired, this step usually isn't needed at all: the moment a `require_owner_signature` operation is requested, the server itself reuses the same paired session to open a live NIP-46 connection and ask your signer app to sign a small, human-readable approval event right then - a real push prompt on your signer app, no command to run. Approving there marks the ticket approved directly; declining, timing out (`YUNOHOST_MCP_OWNER_PUSH_APPROVAL_TIMEOUT_SECONDS`, default 90s), or no session being paired yet just leaves the ticket pending for a manual `yunohost-mcp-approve approve` as above. Disable entirely with `YUNOHOST_MCP_OWNER_PUSH_APPROVAL_ENABLED=false`.

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
