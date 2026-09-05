---
name: yunohost-mcp
description: Set up and diagnose a secure, Nostr-authenticated YunoHost MCP connection in Hermes Agent.
metadata:
  hermes:
    tags: [yunohost, mcp, nostr, self-hosting, administration]
    version: 0.8.4
---

# YunoHost MCP setup

Use the local signed bridge so Hermes can connect to a YunoHost MCP endpoint.

## Setup

1. Ask the user for the YunoHost MCP URL, for example `https://host.example/mcp`.
2. Run:

   ```sh
   uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
     --server https://your-yunohost-domain/mcp \
     --client hermes
   ```

3. Explain that setup creates a per-client Nostr identity and writes Hermes'
   MCP configuration.
4. Never print or request the private key contents.
5. Tell the user to enrol the displayed npub with the appropriate YunoHost
   role, restart Hermes, and run the doctor command printed by setup.

## Diagnosis

If the connection fails, verify the remote URL, confirm the npub has the
required YunoHost role, check that the key file is readable only by the user,
and rerun the printed doctor command.
