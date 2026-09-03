"""yunohost-mcp-approve: the external NIP-46 approval helper
(owner-approval-plan.md).

The owner's private key never touches yunohost-mcp itself (server.py's
approve_operation only ever sees a signed NIP-98 event, never a key) and
must never touch this process either - that's the entire point of NIP-46
(https://nips.nostr.com/46): a remote signer app (Amber, nsec.app, a
hardware signer, ...) holds the owner's real key, and this helper only
ever talks to that signer over an encrypted Nostr channel, asking it to
sign one event at a time. This process does hold one local secret key of
its own - a disposable "app" keypair used only to establish and maintain
that encrypted channel (the NIP-46 spec's own client key) - which is not
the owner's key, grants no authority by itself (every actual signature
still requires the live signer's approval), and is safe to regenerate by
re-pairing if lost.

Two actions:

  yunohost-mcp-approve pair
      One-time setup: print a nostrconnect:// URI (and a QR code, if the
      optional `qrcode` package is installed) for the owner to scan/open
      in their NIP-46 signer app, then wait for it to connect. Persists a
      reconnectable bunker:// session locally (see ApprovalSession) so
      later `approve` calls don't need to re-pair every time.

  yunohost-mcp-approve approve --server <url> --confirmation-id <id>
      Fetches the authoritative pending-confirmation record from the
      server (approval_get - never trusts a locally-supplied plan/hash),
      displays it, requires an explicit interactive "yes", and - only
      then - asks the paired signer to sign a NIP-98 event authorizing
      approve_operation. Both requests to the server are independently
      NIP-98-signed through the live NIP-46 round trip; nothing here ever
      constructs or claims a signature on the signer's behalf.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import secrets
import sys
import urllib.parse
from datetime import timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from nostr_sdk import EventBuilder, Keys, Kind, NostrConnect, NostrConnectUri, Tag

NIP98_KIND = 27235
APP_NAME = "yunohost-mcp-approve"
# Narrowest signer permission this helper ever needs (owner-approval-plan.md:
# "Request the narrowest signer permissions possible... only sign the
# NIP-98 request needed for owner approval") - not blanket sign_event.
NIP46_PERMS = f"sign_event:{NIP98_KIND}"
DEFAULT_RELAYS = ["wss://relay.nsec.app"]
DEFAULT_TIMEOUT_SECONDS = 120


class ApprovalHelperError(RuntimeError):
    """A configuration, pairing, or approval-flow problem this CLI can explain to the user."""


@dataclasses.dataclass
class ApprovalSession:
    """Persisted locally (0600) so `approve` doesn't need to re-pair (scan
    a fresh QR code) on every call. `app_secret_key` is this helper's own
    disposable NIP-46 channel key - see this module's docstring for why
    that's not the same risk as storing the owner's nsec. `bunker_uri` is
    None until `pair` completes; the reconnectable bunker:// URI
    (signer pubkey + relay + secret) afterward."""

    app_secret_key: str
    bunker_uri: str | None = None

    @classmethod
    def fresh(cls) -> ApprovalSession:
        return cls(app_secret_key=Keys.generate().secret_key().to_hex())

    @classmethod
    def load(cls, path: Path) -> ApprovalSession | None:
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return cls(app_secret_key=data["app_secret_key"], bunker_uri=data.get("bunker_uri"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dataclasses.asdict(self)))
        path.chmod(0o600)

    def app_keys(self) -> Keys:
        return Keys.parse(self.app_secret_key)


def default_session_path() -> Path:
    return Path(
        os.environ.get("YUNOHOST_MCP_APPROVE_SESSION_FILE")
        or Path.home() / ".config" / "yunohost-mcp" / "approve-session.json"
    )


def _relays_from_env_or_default() -> list[str]:
    raw = os.environ.get("YUNOHOST_MCP_APPROVE_RELAYS")
    if not raw:
        return list(DEFAULT_RELAYS)
    return [r.strip() for r in raw.split(",") if r.strip()]


def _build_nostrconnect_uri(*, app_pubkey_hex: str, relays: list[str], secret: str) -> str:
    """https://nips.nostr.com/46's nostrconnect:// bootstrap form - a
    query string built by hand (not urllib.parse.urlencode(doseq=True))
    because `relay` must appear once per relay, not comma-joined.

    `secret` and `metadata` are both mandatory for this scheme (unlike
    bunker://, where secret is optional) - rust-nostr's own parser
    (nostr/src/nips/nip46.rs) rejects a nostrconnect:// URI missing
    either, confirmed empirically against nostr-sdk 0.45's
    NostrConnectUri.parse(). `metadata` carries the app name as a single
    JSON-encoded query value, not a flat `name=` param - there is no such
    param; passing one is silently ignored, not an error, which is easy
    to mistake for "it worked" during manual testing.
    """
    params = [("relay", r) for r in relays]
    params += [
        ("secret", secret),
        ("perms", NIP46_PERMS),
        ("metadata", json.dumps({"name": APP_NAME})),
    ]
    query = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in params)
    return f"nostrconnect://{app_pubkey_hex}?{query}"


def _print_qr_if_available(uri: str) -> None:
    """Best-effort - owner-approval-plan.md says "where supported", not
    required. Silently falls back to the printed URI text alone (already
    printed by the caller) when the optional `qrcode` package isn't
    installed; this helper does not depend on it."""
    try:
        import qrcode
    except ImportError:
        print("(install the optional 'qrcode' package for a scannable QR code)", file=sys.stderr)
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    qr.print_ascii(out=sys.stderr, invert=True)


async def _pair(args: argparse.Namespace) -> None:
    session_path = Path(args.session_file)
    existing = ApprovalSession.load(session_path)
    if existing and existing.bunker_uri and not args.repair:
        raise ApprovalHelperError(
            f"already paired (session at {session_path}) - pass --repair to pair again "
            "(e.g. after switching signer apps or losing the session)"
        )

    session = ApprovalSession.fresh()
    app_keys = session.app_keys()
    relays = args.relay or _relays_from_env_or_default()
    secret = secrets.token_hex(16)
    uri = _build_nostrconnect_uri(app_pubkey_hex=app_keys.public_key().to_hex(), relays=relays, secret=secret)

    print(f"{APP_NAME}: open this in the owner's NIP-46 signer app:", file=sys.stderr)
    print(uri, file=sys.stderr)
    _print_qr_if_available(uri)
    print(f"{APP_NAME}: waiting up to {args.timeout}s for the signer to connect...", file=sys.stderr)

    connect = NostrConnect(NostrConnectUri.parse(uri), app_keys, timedelta(seconds=args.timeout), None)
    signer_pubkey = await connect.get_public_key_async()
    if signer_pubkey is None:
        raise ApprovalHelperError("pairing timed out or was rejected by the signer")

    session.bunker_uri = str(await connect.bunker_uri())
    session.save(session_path)
    print(f"{APP_NAME}: paired with signer {signer_pubkey.to_bech32()}", file=sys.stderr)
    print(f"{APP_NAME}: session saved to {session_path}", file=sys.stderr)


def _connect_from_session(session: ApprovalSession, *, timeout_seconds: int) -> NostrConnect:
    if not session.bunker_uri:
        raise ApprovalHelperError(f"{APP_NAME}: not paired yet - run `{APP_NAME} pair` first")
    return NostrConnect(
        NostrConnectUri.parse(session.bunker_uri), session.app_keys(), timedelta(seconds=timeout_seconds), None
    )


class Nip46Auth(httpx2.Auth):
    """Signs every outgoing request with a fresh NIP-98 event (auth/nip98.py's
    server-side counterpart), obtained by asking the paired NIP-46 signer
    to sign it - never a locally-held key. Mirrors bridge.py's
    Nip98BridgeAuth exactly in the header it produces; only *how* the
    event gets signed differs (a live round trip through `connect`,
    not coincurve on a local private key)."""

    requires_request_body = True

    def __init__(self, connect: NostrConnect) -> None:
        self.connect = connect

    async def async_auth_flow(self, request):  # noqa: ANN001 - httpx2's own Request type
        # Overriding async_auth_flow (not auth_flow) bypasses the base
        # class's own automatic request.aread() for requires_request_body -
        # that machinery only runs for auth_flow-based subclasses. Read it
        # ourselves so `request.content` below is always populated, even
        # for a body given as a stream rather than materialized upfront.
        await request.aread()
        body = request.content or b""
        tags = [Tag.parse(["u", str(request.url)]), Tag.parse(["method", request.method.upper()])]
        if body:
            tags.append(Tag.parse(["payload", hashlib.sha256(body).hexdigest()]))
        event = await EventBuilder(Kind(NIP98_KIND), "").tags(tags).finalize_async(self.connect)
        request.headers["Authorization"] = f"Nostr {base64.b64encode(event.as_json().encode()).decode()}"
        yield request


async def _call_tool(server_url: str, auth: httpx2.Auth, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(120.0)) as http_client:
        transport = streamable_http_client(server_url, http_client=http_client)
        async with Client(transport) as client:
            result = await client.call_tool(tool, arguments)
    if result.is_error:
        raise ApprovalHelperError(f"{tool} failed: {result.content}")
    if result.structured_content is None:
        raise ApprovalHelperError(f"{tool} returned no structured content: {result.content}")
    return result.structured_content


def _print_pending_operation(record: dict[str, Any]) -> None:
    print(f"{APP_NAME}: pending operation", file=sys.stderr)
    print(f"  tool:              {record['tool']}", file=sys.stderr)
    print(f"  requester:         {record['requester_pubkey']}", file=sys.stderr)
    print(f"  operation_hash:    {record['operation_hash']}", file=sys.stderr)
    print(f"  expires_at:        {record['expires_at']}", file=sys.stderr)
    print(f"  operation_plan:    {json.dumps(record['operation_plan'], indent=2)}", file=sys.stderr)
    if record["approved"]:
        print(f"  already approved by: {record['approved_by']}", file=sys.stderr)


def _confirm_interactively() -> bool:
    """An explicit "yes", never a default - owner-approval-plan.md's
    approval helper "requires an explicit local confirmation". A
    non-interactive stdin (EOF, redirected /dev/null, ...) is treated as
    "no", not as "assume yes and proceed" - approving a high-risk
    operation must never happen because a prompt silently had nothing to
    read from."""
    try:
        answer = input("Approve this operation? Type 'yes' to confirm: ")
    except EOFError:
        return False
    return answer.strip().lower() == "yes"


async def _async_approve(args: argparse.Namespace) -> None:
    session = ApprovalSession.load(Path(args.session_file))
    if session is None:
        raise ApprovalHelperError(f"{APP_NAME}: not paired yet - run `{APP_NAME} pair` first")
    connect = _connect_from_session(session, timeout_seconds=args.timeout)
    auth = Nip46Auth(connect)

    record = await _call_tool(args.server, auth, "approval_get", {"confirmation_id": args.confirmation_id})
    _print_pending_operation(record)

    if record["approved"]:
        print(f"{APP_NAME}: already approved - nothing to do", file=sys.stderr)
        return

    if not _confirm_interactively():
        print(f"{APP_NAME}: not approved", file=sys.stderr)
        return

    result = await _call_tool(args.server, auth, "approve_operation", {"confirmation_id": args.confirmation_id})
    if result["operation_hash"] != record["operation_hash"]:
        # Should be unreachable (approve_operation doesn't recompute the
        # hash from anything this helper sent) - checked anyway, since a
        # mismatch here would mean the two calls somehow addressed
        # different tickets, and the whole point of operation_hash is to
        # catch exactly that class of mistake before trusting the result.
        raise ApprovalHelperError("operation_hash changed between approval_get and approve_operation - aborting")
    print(f"{APP_NAME}: approved. The requester may now retry its original call.", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME, description="NIP-46 owner approval helper for yunohost-mcp (owner-approval-plan.md)."
    )
    parser.add_argument(
        "--session-file",
        default=str(default_session_path()),
        help="path to this helper's local session file (see $YUNOHOST_MCP_APPROVE_SESSION_FILE)",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="seconds to wait for the NIP-46 signer"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    pair_parser = subparsers.add_parser("pair", help="one-time setup: pair with the owner's NIP-46 signer")
    pair_parser.add_argument(
        "--relay",
        action="append",
        help="relay to use for pairing (repeatable; see $YUNOHOST_MCP_APPROVE_RELAYS, default %s)"
        % DEFAULT_RELAYS,
    )
    pair_parser.add_argument("--repair", action="store_true", help="pair again even if already paired")

    approve_parser = subparsers.add_parser("approve", help="review and approve one pending confirmation")
    approve_parser.add_argument(
        "--server", default=os.environ.get("YUNOHOST_MCP_APPROVE_SERVER"), help="e.g. https://your-domain/mcp"
    )
    approve_parser.add_argument("--confirmation-id", required=True)

    return parser


def main() -> None:
    args = _build_parser().parse_args()

    if args.action == "approve" and not args.server:
        raise ApprovalHelperError("no --server given, and $YUNOHOST_MCP_APPROVE_SERVER is not set")

    try:
        if args.action == "pair":
            anyio.run(_pair, args)
        else:
            anyio.run(_async_approve, args)
    except ApprovalHelperError as exc:
        print(f"{APP_NAME}: error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
