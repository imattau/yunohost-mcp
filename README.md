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

## Development

```
uv sync --group dev
uv run pytest -q
```
