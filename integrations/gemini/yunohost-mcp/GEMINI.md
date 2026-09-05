# YunoHost MCP

This extension connects Gemini CLI to a user-selected YunoHost MCP server
through the local `yunohost-mcp-connect` bridge.

Before using the server, run:

```bash
uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
  --server https://your-yunohost-domain/mcp \
  --client gemini
```

The generated client npub must be granted an appropriate role on the YunoHost
server. Never request or display the private key.
