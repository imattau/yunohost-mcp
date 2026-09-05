---
name: yunohost-mcp-setup
description: Set up or diagnose a connection from OpenCode to a YunoHost MCP server.
---

# YunoHost MCP setup

When the user asks to connect OpenCode to YunoHost MCP:

1. Ask for the server MCP URL if it is not already known.
2. Run `uvx --from yunohost-mcp-connect yunohost-mcp-connect setup --server <URL> --client opencode --non-interactive --format json`.
3. Never request, display, or copy the private key.
4. Explain that the generated npub must be granted the desired role on the YunoHost server.
5. After enrolment, restart or reload OpenCode and run the doctor command from setup.
6. Stop at authentication, authorization, confirmation, or owner-approval boundaries.
