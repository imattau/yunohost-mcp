---
name: setup
description: Set up or diagnose a connection from Claude Code to a YunoHost MCP server.
---

# YunoHost MCP setup

This is an onboarding-only plugin. It deliberately does not start an MCP
server until setup has collected a server URL and created a local key.

When the user asks to connect Claude Code to YunoHost MCP:

1. Ask for the server's MCP URL if it is not already known.
2. Run `uvx --from yunohost-mcp-connect yunohost-mcp-connect setup --server <URL> --client claude-code --non-interactive --format json`.
3. Never request, display, or copy the private key. The command stores it locally.
4. Show the user the generated npub and explain that it must be granted the desired role on the YunoHost server.
5. After enrolment, reload the MCP plugins or restart Claude Code.
6. Run the reported doctor command and stop at authentication, authorization, confirmation, or owner-approval boundaries.
