# Agent integrations

The `yunohost-mcp-connect` package is the shared local stdio bridge. Each
client gets a separate key file and therefore a separate Nostr identity on the
YunoHost server.

## Codex

Install the plugin from the Codex plugin distribution containing
`integrations/codex/yunohost-mcp`, then ask Codex to set up or diagnose the
connection.

## Claude Code

Add this repository as a Claude Code marketplace, then install the
`yunohost-mcp` plugin:

```text
/plugin marketplace add https://github.com/imattau/yunohost-mcp
/plugin install yunohost-mcp@yunohost-mcp
```

## Gemini CLI

Install the extension from this repository's Gemini integration directory or
GitHub release, then run the extension's setup flow. The extension configures
the local `uvx` bridge and uses `~/.gemini/settings.json`.

## Hermes

Run:

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
  --server https://your-yunohost-domain/mcp \
  --client hermes
```

## OpenCode

Run:

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
  --server https://your-yunohost-domain/mcp \
  --client opencode
```

The generated config uses OpenCode's local MCP server shape. See
`integrations/opencode/yunohost-mcp/opencode.json.example` for a manual setup.

## OpenClaw

Install the `yunohost-mcp` skill from ClawHub, then ask OpenClaw to run its
setup flow. Direct setup is also available:

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
  --server https://your-yunohost-domain/mcp \
  --client openclaw
```

## Publication checklist

- PyPI: publish `yunohost-mcp-connect` first. This is the package artifact used
  by the clients and by the MCP Registry metadata.
- MCP Registry: publish a GitHub release. The
  `.github/workflows/publish-registry.yml` workflow authenticates with GitHub
  OIDC and publishes `server.json`; it also aligns the registry version with
  the release tag. Verify it with:

  ```bash
  curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.imattau/yunohost-mcp"
  ```

- Claude Code: the repository root contains a Claude marketplace manifest, so
  the repository URL can be added as a marketplace.
- Codex: the integration is a valid plugin bundle, but it still needs to be
  submitted to whichever public Codex plugin marketplace/distribution channel
  you choose; the repository does not imply marketplace registration.
- Hermes: publish the setup skill to the Hermes Skills Hub, or publish the
  repository as a Hermes tap and let users install `yunohost-mcp` from it.
- OpenClaw: publish the setup skill to ClawHub with `clawhub skill publish`.

The MCP Registry entry advertises the distributable server package. Client
installations still use the `yunohost-mcp-connect` bridge because YunoHost
connections require per-user Nostr keys and a site-specific remote URL.
