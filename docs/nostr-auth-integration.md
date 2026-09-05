# Nostr identity integration contract

This document defines the boundary between `yunohost-nostr-auth` and
`yunohost-mcp`. The projects may share a Nostr identity, but they do not share
an authorization decision.

## Canonical identity

- Store and compare the x-only public key as 64 lowercase hexadecimal
  characters.
- Accept `npub1...` only at human/configuration boundaries and normalize it to
  hex immediately.
- Never accept or persist an `nsec` where a public identity is expected.
- A pubkey is an identity, not an administrative grant.

## Separate responsibilities

```text
pubkey
  ├── nostr_auth: linked YunoHost username and portal-session eligibility
  └── yunohost-mcp: MCP roles, scopes, delegation and approval policy
```

MCP may optionally display or audit a linked YunoHost username, but account
linkage must not grant MCP scopes. MCP identity configuration remains
deny-by-default and is authoritative for management capabilities.

The group-backed provider uses `nostr_auth`'s separate private lookup socket,
not its SQLite database. MCP sends one lowercase public-key hex value and
receives only `{linked, username}`. The socket is read-only, non-enumerable,
and independently protected with filesystem permissions and `SO_PEERCRED`.
It is configured with `YUNOHOST_MCP_NOSTR_AUTH_LOOKUP_SOCKET`.

## Optional correlation record

If the projects need a shared read-only identity view, its minimum shape is:

```json
{
  "pubkey": "64 lowercase hex characters",
  "npub": "npub1...",
  "yunohost_username": "optional username",
  "linked": true
}
```

The MCP must treat `yunohost_username` as metadata only. It must not use this
record to infer a role, scope, administrator status, or owner-approval right.

## Authentication flows

`nostr_auth` continues to own browser login and portal session minting:

```text
challenge → signed event → linked account → YunoHost portal cookie
```

MCP continues to own request authentication:

```text
NIP-98 signed HTTP request → identity provider → scopes/policy
```

The flows can use the same pubkey without sharing challenge stores, cookies,
or session state.

## Privilege boundary

Both projects use long-running Unix-socket helpers rather than per-request
`sudo`. The MCP helper must additionally verify the original NIP-98 envelope,
identity/delegation state and operation scope before invoking a fixed
YunoHost operation. The frontend must never send a trusted `authorized` or
`scopes` flag to the helper.
