"""yunohost-mcp-delegate: build and sign a Nostr capability delegation event
(PLAN.md Phase 11, auth/delegation.py) - the tool that was missing to
actually *create* one.

Everything server-side to verify and consume a delegation already existed
(auth/delegation.py's verify_delegation_event/resolve_delegated_identity,
exercised by the middleware and by tests); the only thing that could sign
one was a test helper. This is the real, standalone client-side
counterpart: an owner (someone with an identity.toml entry) runs this to
grant a subset of their own scopes to a disposable agent identity, for a
bounded time, without ever handing over their own private key - the
delegate authenticates with its *own* key as always (auth/nip98.py) and
just additionally presents the signed delegation alongside it.

The output is a JSON delegation event, written to a file the delegate
passes to `yunohost-mcp-connect --delegation-file` (or the equivalent
$YUNOHOST_MCP_CLIENT_DELEGATION_FILE). It is a bearer credential once
issued - anyone holding the file can present it - so it should be handed
to the delegate over a channel you trust, the same as you'd treat an API
key.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from pathlib import Path

import anyio
import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from yunohost_mcp.auth.delegation import DEFAULT_MAX_LIFETIME_SECONDS, DELEGATION_KIND
from yunohost_mcp.auth.nostr import NostrEvent, sign_event
from yunohost_mcp.auth.npub import Bech32Error, hex_to_npub, npub_to_hex
from yunohost_mcp.auth.signing import ClientIdentity
from yunohost_mcp.bridge import BridgeConfigError, Nip98BridgeAuth, load_identity
from yunohost_mcp.policy.roles import ROLE_SCOPES
from yunohost_mcp.policy.scopes import Scope

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_duration(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([A-Za-z]*)\s*", value)
    if not match:
        raise BridgeConfigError(f"not a duration (e.g. '24h', '7d'): {value!r}")
    number, unit = match.groups()
    unit = unit.lower() or "h"
    try:
        multiplier = _DURATION_UNITS[unit]
    except KeyError:
        raise BridgeConfigError(f"unknown duration unit {unit!r} in {value!r} (use s/m/h/d)") from None
    return int(number) * multiplier


def _resolve_pubkey(raw: str, *, what: str) -> str:
    raw = raw.strip()
    if raw.startswith("npub1"):
        try:
            return npub_to_hex(raw)
        except Bech32Error as exc:
            raise BridgeConfigError(f"{what}: {exc}") from exc
    if raw.startswith("nsec1"):
        raise BridgeConfigError(f"{what}: looks like a private key (nsec1...) - this must be a public key")
    return raw.lower()


def _resolve_scopes(args: argparse.Namespace) -> list[str]:
    scopes: set[str] = set()
    for role in args.role or []:
        try:
            scopes |= {s.value for s in ROLE_SCOPES[role]}
        except KeyError:
            raise BridgeConfigError(f"unknown role {role!r}; known roles: {sorted(ROLE_SCOPES)}") from None
    for scope in args.scope or []:
        try:
            scopes.add(Scope(scope).value)
        except ValueError:
            raise BridgeConfigError(
                f"unknown scope {scope!r}; known scopes: {sorted(s.value for s in Scope)}"
            ) from None
    if not scopes:
        raise BridgeConfigError("nothing to delegate - pass --scope and/or --role at least once")
    return sorted(scopes)


async def _fetch_server_context(remote_url: str, identity: ClientIdentity) -> tuple[str, list[str]]:
    """Query the server itself (as this owner) for its pubkey and this
    owner's own current scopes - so --server doesn't have to be typed by
    hand, and so an over-broad --scope request can be flagged before
    signing anything, not silently clipped later by the server."""
    auth = Nip98BridgeAuth(identity)
    async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(30.0)) as http_client:
        transport = streamable_http_client(remote_url, http_client=http_client)
        async with Client(transport) as remote:
            server_result = await remote.call_tool("server_identity", {})
            server_data = server_result.structured_content or {}
            server_pubkey = server_data.get("pubkey")
            if not server_pubkey:
                raise BridgeConfigError(f"server_identity did not return a pubkey: {server_data!r}")

            who_result = await remote.call_tool("whoami", {})
            who_data = who_result.structured_content or {}
            if not who_data.get("authenticated"):
                raise BridgeConfigError(
                    "server rejected this key's own identity (whoami returned unauthenticated) - "
                    "you need your own identity.toml entry before you can delegate anything"
                )
            own_scopes = list(who_data.get("scopes", []))
            return server_pubkey, own_scopes


def _sign_delegation(
    identity: ClientIdentity,
    *,
    delegate_pubkey: str,
    server_pubkey: str,
    scopes: list[str],
    ttl_seconds: int,
) -> NostrEvent:
    if ttl_seconds > DEFAULT_MAX_LIFETIME_SECONDS:
        raise BridgeConfigError(
            f"--ttl of {ttl_seconds}s exceeds the maximum a server will accept "
            f"({DEFAULT_MAX_LIFETIME_SECONDS}s / 30d) - use a shorter --ttl"
        )
    created_at = int(time.time())
    expires_at = created_at + ttl_seconds
    tags = [["p", delegate_pubkey], ["server", server_pubkey], ["expiry", str(expires_at)]]
    tags += [["scope", s] for s in scopes]
    return sign_event(
        identity.private_key, pubkey=identity.pubkey_hex, kind=DELEGATION_KIND, tags=tags, created_at=created_at
    )


async def _async_main(args: argparse.Namespace) -> None:
    identity = load_identity(args)
    delegate_pubkey = _resolve_pubkey(args.delegate, what="--delegate")
    scopes = _resolve_scopes(args)

    own_scopes: list[str] | None = None
    if args.server:
        server_pubkey = _resolve_pubkey(args.server, what="--server")
    else:
        if not args.remote_url:
            raise BridgeConfigError(
                "no --server given - pass --server explicitly, or --remote-url "
                "(or $YUNOHOST_MCP_CLIENT_REMOTE_URL) to fetch it from the server"
            )
        print(f"yunohost-mcp-delegate: contacting {args.remote_url} as {identity.npub}...", file=sys.stderr)
        server_pubkey, own_scopes = await _fetch_server_context(args.remote_url, identity)

    if own_scopes is not None:
        excess = sorted(set(scopes) - set(own_scopes))
        if excess:
            print(
                f"warning: you do not currently hold {excess} - the server will silently drop "
                "these from the delegation rather than reject it (a delegation can never exceed "
                "its delegator's own current scopes); re-run with only scopes you actually have "
                "if that's not what you intended",
                file=sys.stderr,
            )

    ttl_seconds = _parse_duration(args.ttl)
    event = _sign_delegation(
        identity,
        delegate_pubkey=delegate_pubkey,
        server_pubkey=server_pubkey,
        scopes=scopes,
        ttl_seconds=ttl_seconds,
    )

    payload = json.dumps(event.model_dump(), indent=2) + "\n"
    if args.out:
        out_path = Path(args.out)
        out_path.write_text(payload)
        out_path.chmod(0o600)
        print(f"yunohost-mcp-delegate: wrote delegation to {out_path}", file=sys.stderr)
    else:
        sys.stdout.write(payload)

    header_b64 = base64.b64encode(json.dumps(event.model_dump()).encode()).decode()
    expires_local = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(event.tag("expiry") or 0)))
    print(
        f"\nDelegate:      {hex_to_npub(delegate_pubkey)}\n"
        f"Server:        {hex_to_npub(server_pubkey)}\n"
        f"Scopes:        {', '.join(scopes)}\n"
        f"Expires:       {expires_local}\n"
        f"Event id:      {event.id}\n\n"
        "Give the delegate this file (or its base64 form below) to use with:\n"
        "  yunohost-mcp-connect --delegation-file <path>\n"
        "or:\n"
        "  YUNOHOST_MCP_CLIENT_DELEGATION_FILE=<path>\n\n"
        "It is a bearer credential once issued: anyone holding it can act as this delegation "
        "grants until it expires or you revoke it (revoked_delegations.toml, keyed by the event "
        "id above) - hand it over the same way you'd hand over an API key, not in a public channel.\n\n"
        f"X-Nostr-Delegation header value:\n{header_b64}",
        file=sys.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="yunohost-mcp-delegate",
        description=(
            "Sign a delegation event (PLAN.md Phase 11): grant a subset of your own "
            "yunohost-mcp scopes to another Nostr identity, for a bounded time, without "
            "ever sharing your private key."
        ),
    )
    parser.add_argument(
        "--key", help="your own hex or nsec1... private key (prefer --key-file; see $YUNOHOST_MCP_CLIENT_KEY)"
    )
    parser.add_argument(
        "--key-file",
        help="path to a file containing your hex or nsec1... private key (see $YUNOHOST_MCP_CLIENT_KEY_FILE)",
    )
    parser.add_argument("--delegate", required=True, help="the agent's pubkey to delegate to (npub1... or hex)")
    parser.add_argument(
        "--server",
        help="the target server's pubkey (npub1... or hex); omit to fetch it live via --remote-url",
    )
    parser.add_argument(
        "--remote-url",
        default=os.environ.get("YUNOHOST_MCP_CLIENT_REMOTE_URL"),
        help="e.g. https://your-domain/mcp - used to fetch --server and sanity-check --scope if --server is omitted",
    )
    parser.add_argument(
        "--scope",
        action="append",
        help=f"a scope to grant (repeatable); known scopes: {', '.join(sorted(s.value for s in Scope))}",
    )
    parser.add_argument(
        "--role",
        action="append",
        help=f"grant every scope in a role (repeatable); known roles: {', '.join(sorted(ROLE_SCOPES))}",
    )
    parser.add_argument(
        "--ttl",
        default="24h",
        help="how long the delegation is valid for, e.g. '24h', '7d' (default: 24h; server rejects anything over 30d)",
    )
    parser.add_argument("--out", help="write the signed delegation event JSON to this file (default: stdout)")
    args = parser.parse_args()

    anyio.run(_async_main, args)


if __name__ == "__main__":
    main()
