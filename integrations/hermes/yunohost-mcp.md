# YunoHost MCP for Hermes

Hermes can use the same local signed bridge as other MCP clients. Run:

```sh
uvx --from yunohost-mcp-connect yunohost-mcp-connect setup \
  --server https://your-yunohost-domain/mcp \
  --client hermes
```

This writes `~/.hermes/config.yaml` with a local stdio MCP server using `uvx`.
The generated client npub must still be granted an appropriate role on the
YunoHost server. After enrolment, restart Hermes and run the doctor command
printed by setup.
