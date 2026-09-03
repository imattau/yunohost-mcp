# yunohost-mcp

Secure MCP server for YunoHost: Nostr-authenticated, policy-controlled, auditable administration, diagnostics, and `_ynh` package development for AI clients (Codex, Claude, OpenCode, ChatGPT-compatible MCP clients).

See [PLAN.md](PLAN.md) for the full design and phased roadmap, and [PHASE0_INVESTIGATION.md](PHASE0_INVESTIGATION.md) for how it maps onto YunoHost's actual Python API.

## Running the server

```
yunohost-mcp --transport stdio   # local development, fully trusted (no NIP-98 handshake)
yunohost-mcp --transport http --host 127.0.0.1 --port 8765   # NIP-98-authenticated, remote-capable
```

By default `fake_yunohost` is off (real mode) — set `YUNOHOST_MCP_FAKE_YUNOHOST=true` to run against canned data on a machine without YunoHost installed. See `identity.example.toml` for `identity.toml`'s shape (pubkey → role mapping; required before any HTTP request can do anything).

## Connecting a client: yunohost-mcp-connect

Mainstream MCP clients (Claude Desktop, a plain Codex install, etc.) have no way to sign a NIP-98 `Authorization` header — that's specific to this server. `yunohost-mcp-connect` bridges the gap: a small local process that speaks plain MCP over stdio to your actual client, and forwards every request to the remote `--transport http` server, signed with your own Nostr key.

```
yunohost-mcp-connect --remote-url https://your-yunohost-domain/mcp --key-file ~/.config/yunohost-mcp/key
```

- `--key-file` (or `$YUNOHOST_MCP_CLIENT_KEY_FILE`) points at a file holding a hex or `nsec1...` private key — preferred over `--key`/`$YUNOHOST_MCP_CLIENT_KEY`, which put the key in argv/environment where other processes on the same machine can read it.
- `--delegation-file` (or `$YUNOHOST_MCP_CLIENT_DELEGATION_FILE`) presents a delegation event (PLAN.md Phase 11) alongside your own signature, for a disposable agent identity an owner granted a subset of their access to.
- Point your MCP client's config at this command (not the server directly) — `tools/list`, `tools/call`, `resources/list`, and `resources/read` are all forwarded verbatim; every other MCP feature and all authorization/policy/audit still happens exactly as it would if you'd signed the request yourself, because you did.

## Connecting Claude Desktop or Codex

Both point at `yunohost-mcp-connect`, not at the server directly — the bridge is what signs each request with your Nostr key. Use the full path to `yunohost-mcp-connect` in whatever environment you installed `yunohost-mcp` into (e.g. `~/.local/pipx/venvs/yunohost-mcp/bin/yunohost-mcp-connect`, or a venv's `bin/` directory — `which yunohost-mcp-connect` after activating it will tell you).

**Claude Desktop** (`claude_desktop_config.json` — Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "yunohost-mcp": {
      "command": "/full/path/to/yunohost-mcp-connect",
      "env": {
        "YUNOHOST_MCP_CLIENT_REMOTE_URL": "https://your-yunohost-domain/mcp",
        "YUNOHOST_MCP_CLIENT_KEY_FILE": "/home/you/.config/yunohost-mcp/key"
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
YUNOHOST_MCP_CLIENT_KEY_FILE = "/home/you/.config/yunohost-mcp/key"
```

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

## Development

```
uv sync --group dev
uv run pytest -q
```

## Creating a release tag

Maintainers can run the GitHub Actions **Tag release** workflow manually from
the branch or commit to release, providing a version without the `v` prefix
(for example, `0.1.1`). It validates the version, refuses to overwrite an
existing tag, and pushes an annotated `v<version>` tag.
