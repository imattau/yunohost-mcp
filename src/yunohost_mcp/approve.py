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

Four actions:

  yunohost-mcp-approve offer
      Print (and persist, see PendingOffer) a pairing link/QR without
      listening for anything yet - for a caller that wants a stable,
      always-visible code before any button click (a webadmin config
      panel's "Signer status" display, say), rather than only ever
      showing a link inside a one-shot action's scrolling log output.
      Idempotent: repeated calls return the same link until it expires
      (OFFER_TTL_SECONDS), is consumed by a successful `pair`, or
      --regenerate is passed.

  yunohost-mcp-approve pair
      One-time setup: reuses any pending `offer` link (so whatever was
      already shown/scanned keeps working), or generates one if none
      exists, then waits for the signer to connect. Persists a
      reconnectable bunker:// session locally (see ApprovalSession) so
      later `approve` calls don't need to re-pair every time.

      Which relays an offer advertises: an explicit --relay (repeatable)
      is used exactly as given. Otherwise, --owner-npub triggers a
      best-effort NIP-65 (kind 10002) lookup of the owner's own published
      relay list on a small set of discovery relays, preferring those
      (plus any --extra-relay) over the plain DEFAULT_RELAYS fallback -
      pairing over relays the owner's signer is actually likely to be
      listening on, rather than a fixed guess. See resolve_pair_relays.

  yunohost-mcp-approve status
      Local-only, no network: reports whether a session is paired yet
      (and the paired signer's pubkey, if so) by reading the session
      file alone. For a caller (e.g. a webadmin config panel) that wants
      to show pairing state without waiting on a live NIP-46 round trip.

  yunohost-mcp-approve approve --server <url> --confirmation-id <id>
      Fetches the authoritative pending-confirmation record from the
      server (approval_get - never trusts a locally-supplied plan/hash),
      displays it, requires an explicit interactive "yes" (unless --yes
      is given - see below), and - only then - asks the paired signer to
      sign a NIP-98 event authorizing approve_operation. Both requests to
      the server are independently NIP-98-signed through the live NIP-46
      round trip; nothing here ever constructs or claims a signature on
      the signer's behalf.

      --yes skips the interactive "Type 'yes' to confirm" prompt. Only
      for a caller that already gates this action behind its own
      explicit confirmation step (a webadmin action button the owner
      deliberately clicked, having just been shown the operation_plan
      output from this same command) - never a default, and never wired
      up for unattended/scheduled use, since the whole point of owner
      approval is a human looking at operation_hash before it executes.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import logging
import os
import secrets
import sys
import time
import urllib.parse
from datetime import timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from nostr_sdk import Client as NostrClient
from nostr_sdk import EventBuilder, Filter, Keys, Kind, NostrConnect, NostrConnectUri, PublicKey, RelayUrl, Tag

from yunohost_mcp.auth.npub import Bech32Error, npub_to_hex

NIP98_KIND = 27235
NIP65_RELAY_LIST_KIND = 10002
APP_NAME = "yunohost-mcp-approve"
# Narrowest signer permission this helper ever needs (owner-approval-plan.md:
# "Request the narrowest signer permissions possible... only sign the
# NIP-98 request needed for owner approval") - not blanket sign_event.
NIP46_PERMS = f"sign_event:{NIP98_KIND}"
# A few broadly reliable, unauthenticated public relays - not tied to any
# one signer vendor. Used only when nothing more specific is available:
# an explicit --relay, and (below) the owner's own NIP-65 relay list.
DEFAULT_RELAYS = ["wss://relay.nsec.app", "wss://relay.damus.io", "wss://nos.lol"]
# Where to look up the owner's own NIP-65 (kind 10002) relay list, if
# --owner-npub is given - general-purpose discovery/indexer relays, not
# necessarily relays the owner reads/writes to themselves.
DEFAULT_DISCOVERY_RELAYS = ["wss://purplepag.es", "wss://relay.nostr.band", "wss://nos.lol"]
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_DISCOVERY_TIMEOUT_SECONDS = 5

logger = logging.getLogger(__name__)


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


# How long a pending offer (below) stays valid before `offer` silently
# regenerates it rather than handing out a possibly-stale-looking link -
# generous, since this is meant to sit on screen (a webadmin panel) for a
# while before anyone scans it, not a short-lived one-shot token.
OFFER_TTL_SECONDS = 24 * 60 * 60


@dataclasses.dataclass
class PendingOffer:
    """A pairing link/QR generated ahead of time, independent of whether
    anything is actually listening for the signer's response yet - the
    fix for `pair` previously doing both "generate a fresh nostrconnect://
    link" and "block waiting for the signer" in one shot, which meant a
    caller (e.g. a webadmin config panel) had nowhere to show a stable
    link before a button click, and the link changed on every retry.

    `offer` (see cmd below) creates and persists one of these without
    listening for anything; `pair` reuses it (rather than generating a
    fresh secret) so the code someone already scanned keeps working.
    Consumed (deleted) once pairing actually succeeds, or replaced once
    OFFER_TTL_SECONDS has passed - never reused across explicitly
    different relay/owner-npub arguments; see cmd_offer."""

    app_secret_key: str
    secret: str
    relays: list[str]
    uri: str
    created_at: float

    @classmethod
    def fresh(cls, *, relays: list[str]) -> PendingOffer:
        app_keys = Keys.generate()
        secret = secrets.token_hex(16)
        uri = _build_nostrconnect_uri(app_pubkey_hex=app_keys.public_key().to_hex(), relays=relays, secret=secret)
        return cls(
            app_secret_key=app_keys.secret_key().to_hex(),
            secret=secret,
            relays=relays,
            uri=uri,
            created_at=time.time(),
        )

    @classmethod
    def load(cls, path: Path) -> PendingOffer | None:
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return cls(**data)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dataclasses.asdict(self)))
        path.chmod(0o600)

    def is_expired(self, *, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) - self.created_at > OFFER_TTL_SECONDS

    def app_keys(self) -> Keys:
        return Keys.parse(self.app_secret_key)


def default_offer_path() -> Path:
    return Path(
        os.environ.get("YUNOHOST_MCP_APPROVE_OFFER_FILE") or Path.home() / ".config" / "yunohost-mcp" / "approve-offer.json"
    )


def _relays_from_env_or_default() -> list[str]:
    raw = os.environ.get("YUNOHOST_MCP_APPROVE_RELAYS")
    if not raw:
        return list(DEFAULT_RELAYS)
    return [r.strip() for r in raw.split(",") if r.strip()]


def _discovery_relays_from_env_or_default() -> list[str]:
    raw = os.environ.get("YUNOHOST_MCP_APPROVE_DISCOVERY_RELAYS")
    if not raw:
        return list(DEFAULT_DISCOVERY_RELAYS)
    return [r.strip() for r in raw.split(",") if r.strip()]


def _dedupe(relays: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for relay in relays:
        if relay not in seen:
            seen.add(relay)
            result.append(relay)
    return result


def resolve_pair_relays(
    *, explicit: list[str] | None, extra: list[str], discovered: list[str], defaults: list[str]
) -> list[str]:
    """Priority: an explicit --relay (repeatable) is a full override - the
    caller asked for exactly those relays, nothing added. Otherwise, use
    whatever relays were discovered from the owner's own NIP-65 list (or,
    failing that, the plain defaults), plus any --extra-relay the caller
    additionally wants folded in either way."""
    if explicit:
        return _dedupe(explicit)
    base = discovered or defaults
    return _dedupe(base + extra)


def _parse_relay_urls_from_event_tags(event) -> list[str]:  # noqa: ANN001 - nostr_sdk's Event type
    """NIP-65 (kind 10002): one "r" tag per relay, optionally marked
    read/write-only in a third element - any r tag is a relay this pubkey
    is reachable through, so no filtering on that third element here."""
    urls = []
    for tag in event.tags().to_vec():
        parts = tag.to_vec()
        if len(parts) >= 2 and parts[0] == "r":
            urls.append(parts[1])
    return urls


async def _fetch_owner_relay_list(owner_pubkey_hex: str, discovery_relays: list[str], timeout_seconds: int) -> list[str]:
    """Best-effort NIP-65 lookup for the owner's own relay list, so pairing
    defaults to relays the owner is actually likely to be reachable on
    instead of a fixed guess. Never raises - a discovery-relay outage or a
    owner with no published relay list must never block pairing; it just
    falls back to resolve_pair_relays' plain defaults."""
    client = NostrClient()
    try:
        for relay in discovery_relays:
            await client.add_relay(RelayUrl.parse(relay))
        await client.connect()
        filter_ = Filter().author(PublicKey.parse(owner_pubkey_hex)).kind(Kind(NIP65_RELAY_LIST_KIND)).limit(1)
        events = await client.fetch_events(filter_, timeout=timedelta(seconds=timeout_seconds))
        if not events:
            return []
        return _parse_relay_urls_from_event_tags(events[0])
    except Exception:
        logger.warning("owner relay-list discovery failed (non-fatal, falling back to defaults)", exc_info=True)
        return []
    finally:
        await client.shutdown()


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


def _qr_ascii_if_available(uri: str) -> str | None:
    """Best-effort - owner-approval-plan.md says "where supported", not
    required. Returns None (not a printed fallback message here - callers
    decide what, if anything, to say) when the optional `qrcode` package
    isn't installed; this helper does not depend on it."""
    try:
        import io

        import qrcode
    except ImportError:
        return None
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)
    return buf.getvalue()


async def _resolve_relays_for_offer(args: argparse.Namespace) -> list[str]:
    discovered: list[str] = []
    if not args.relay and args.owner_npub:
        try:
            owner_pubkey_hex = npub_to_hex(args.owner_npub) if args.owner_npub.startswith("npub1") else args.owner_npub
        except Bech32Error as exc:
            raise ApprovalHelperError(f"--owner-npub {args.owner_npub!r} is not a valid npub: {exc}") from exc
        print(f"{APP_NAME}: looking up {args.owner_npub}'s own relay list (NIP-65)...", file=sys.stderr)
        discovered = await _fetch_owner_relay_list(
            owner_pubkey_hex, _discovery_relays_from_env_or_default(), DEFAULT_DISCOVERY_TIMEOUT_SECONDS
        )
        if discovered:
            print(f"{APP_NAME}: found {len(discovered)} relay(s) from the owner's own list", file=sys.stderr)
        else:
            print(f"{APP_NAME}: no relay list found for the owner - falling back to defaults", file=sys.stderr)

    return resolve_pair_relays(
        explicit=args.relay,
        extra=args.extra_relay or [],
        discovered=discovered,
        defaults=_relays_from_env_or_default(),
    )


async def _resolve_offer(args: argparse.Namespace, offer_path: Path) -> PendingOffer:
    """The core of the fix for "the pairing link only ever appeared in a
    one-shot, scrolling-away action log": `offer` (below) can call this to
    produce and persist a link *before* anything is listening for it, and
    `pair` calls the same thing to reuse that exact link/secret instead of
    silently handing out a different one every retry - so whatever a
    caller (e.g. a webadmin panel) already displayed keeps working.

    Regenerates only when there's a reason to: no offer yet, --regenerate,
    the existing one expired (OFFER_TTL_SECONDS), or an explicit --relay
    that might name something different than what's cached."""
    existing = None if args.regenerate else PendingOffer.load(offer_path)
    if existing and not existing.is_expired() and not args.relay:
        return existing

    relays = await _resolve_relays_for_offer(args)
    offer = PendingOffer.fresh(relays=relays)
    offer.save(offer_path)
    return offer


async def _offer(args: argparse.Namespace) -> None:
    """Print (and persist) a pairing link/QR without listening for
    anything - see _resolve_offer. Safe to call repeatedly; idempotent
    until the offer expires, is consumed by a successful `pair`, or
    --regenerate is passed."""
    offer = await _resolve_offer(args, Path(args.offer_file))
    print(offer.uri)
    qr_ascii = _qr_ascii_if_available(offer.uri)
    if qr_ascii:
        print(qr_ascii)
    else:
        print("(install the optional 'qrcode' package for a scannable QR code)", file=sys.stderr)


async def _pair(args: argparse.Namespace) -> None:
    session_path = Path(args.session_file)
    existing_session = ApprovalSession.load(session_path)
    if existing_session and existing_session.bunker_uri and not args.repair:
        raise ApprovalHelperError(
            f"already paired (session at {session_path}) - pass --repair to pair again "
            "(e.g. after switching signer apps or losing the session)"
        )

    offer_path = Path(args.offer_file)
    offer = await _resolve_offer(args, offer_path)
    app_keys = offer.app_keys()

    print(f"{APP_NAME}: open this in the owner's NIP-46 signer app:", file=sys.stderr)
    print(offer.uri, file=sys.stderr)
    qr_ascii = _qr_ascii_if_available(offer.uri)
    if qr_ascii:
        print(qr_ascii, file=sys.stderr)
    else:
        print("(install the optional 'qrcode' package for a scannable QR code)", file=sys.stderr)
    print(f"{APP_NAME}: waiting up to {args.timeout}s for the signer to connect...", file=sys.stderr)

    connect = NostrConnect(NostrConnectUri.parse(offer.uri), app_keys, timedelta(seconds=args.timeout), None)
    signer_pubkey = await connect.get_public_key_async()
    if signer_pubkey is None:
        raise ApprovalHelperError("pairing timed out or was rejected by the signer - the same link/QR is still valid, try again")

    session = ApprovalSession(app_secret_key=offer.app_secret_key, bunker_uri=str(await connect.bunker_uri()))
    session.save(session_path)
    offer_path.unlink(missing_ok=True)  # consumed - the next `offer` call generates a fresh one
    print(f"{APP_NAME}: paired with signer {signer_pubkey.to_bech32()}", file=sys.stderr)
    print(f"{APP_NAME}: session saved to {session_path}", file=sys.stderr)


def _print_status(args: argparse.Namespace) -> None:
    session = ApprovalSession.load(Path(args.session_file))
    if session is None or not session.bunker_uri:
        print("paired: false", file=sys.stdout)
        return
    print("paired: true", file=sys.stdout)
    # bunker://<signer-pubkey-hex>?relay=...&secret=... - the signer's
    # pubkey is the URI's host/netloc, not a query param.
    signer_pubkey_hex = urllib.parse.urlparse(session.bunker_uri).netloc
    print(f"signer_pubkey: {signer_pubkey_hex}", file=sys.stdout)


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

    if not args.yes and not _confirm_interactively():
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
        "--offer-file",
        default=str(default_offer_path()),
        help="path to this helper's pending-offer file (see $YUNOHOST_MCP_APPROVE_OFFER_FILE)",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="seconds to wait for the NIP-46 signer"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    def _add_offer_relay_args(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument(
            "--relay",
            action="append",
            help="relay to use for pairing (repeatable). Full override - given this, nothing else "
            "(--owner-npub discovery, --extra-relay, defaults) is added. See $YUNOHOST_MCP_APPROVE_RELAYS.",
        )
        subparser.add_argument(
            "--extra-relay",
            action="append",
            help="an additional relay to fold in alongside whatever --owner-npub discovers (or the plain "
            "defaults, if not given) - repeatable. Ignored if --relay is given.",
        )
        subparser.add_argument(
            "--owner-npub",
            help="the owner's own npub (or hex pubkey) - if given (and --relay is not), pairing looks up "
            f"this pubkey's NIP-65 relay list first and prefers those relays, falling back to "
            f"{DEFAULT_RELAYS} if none is published. See $YUNOHOST_MCP_APPROVE_DISCOVERY_RELAYS for where "
            "that lookup itself happens.",
        )
        subparser.add_argument(
            "--regenerate",
            action="store_true",
            help="get a fresh link/secret even if an unexpired one is already pending (OFFER_TTL_SECONDS) - "
            "normally offer/pair reuse whatever link was already shown, so a code someone already scanned "
            "keeps working.",
        )

    offer_parser = subparsers.add_parser(
        "offer",
        help="print (and persist) a pairing link/QR without listening for anything yet - "
        "for a caller (e.g. a webadmin panel) that wants a stable, always-visible code before any button click",
    )
    _add_offer_relay_args(offer_parser)

    pair_parser = subparsers.add_parser(
        "pair",
        help="one-time setup: pair with the owner's NIP-46 signer, reusing any pending `offer` link if one exists",
    )
    _add_offer_relay_args(pair_parser)
    pair_parser.add_argument("--repair", action="store_true", help="pair again even if already paired")

    subparsers.add_parser("status", help="report whether a signer is paired yet (local-only, no network)")

    approve_parser = subparsers.add_parser("approve", help="review and approve one pending confirmation")
    approve_parser.add_argument(
        "--server", default=os.environ.get("YUNOHOST_MCP_APPROVE_SERVER"), help="e.g. https://your-domain/mcp"
    )
    approve_parser.add_argument("--confirmation-id", required=True)
    approve_parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive 'yes' prompt - only for a caller that already gates this behind its "
        "own explicit confirmation step (see module docstring)",
    )

    return parser


def main() -> None:
    args = _build_parser().parse_args()

    if args.action == "approve" and not args.server:
        raise ApprovalHelperError("no --server given, and $YUNOHOST_MCP_APPROVE_SERVER is not set")

    try:
        if args.action == "offer":
            anyio.run(_offer, args)
        elif args.action == "pair":
            anyio.run(_pair, args)
        elif args.action == "status":
            _print_status(args)
        else:
            anyio.run(_async_approve, args)
    except ApprovalHelperError as exc:
        print(f"{APP_NAME}: error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
