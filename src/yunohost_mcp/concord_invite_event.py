"""Verification of public CORD-05 invite bundle events."""

from __future__ import annotations

from dataclasses import dataclass

from nostr_sdk import Nip19Coordinate

from .auth.nostr import NostrEvent, verify_event


class ConcordInviteEventError(ValueError):
    """A fetched public invite event is malformed, revoked, or unexpected."""


@dataclass(frozen=True)
class InviteCoordinate:
    """The NIP-19 coordinate required to fetch a public invite bundle."""

    author_hex: str
    kind: int
    identifier: str


def decode_invite_naddr(value: str) -> InviteCoordinate:
    """Decode Concord's strict kind-33301, empty-identifier naddr."""

    try:
        parsed = Nip19Coordinate.from_bech32(value)
        coordinate = parsed.coordinate()
    except Exception as exc:  # noqa: BLE001 - normalize rust-nostr parse errors
        raise ConcordInviteEventError("invalid Concord invite naddr") from exc
    identifier = coordinate.identifier()
    author = coordinate.public_key().to_hex()
    kind = coordinate.kind().as_u16()
    if identifier != "" or kind != 33301:
        raise ConcordInviteEventError("Concord invite naddr has the wrong coordinate shape")
    return InviteCoordinate(author_hex=author, kind=kind, identifier=identifier)


def _tag(event: NostrEvent, name: str) -> str | None:
    return event.tag(name)


def extract_invite_ciphertext(event: dict, *, expected_author: str) -> str:
    """Verify a live kind-33301 invite event and return only its ciphertext."""

    try:
        parsed = NostrEvent.model_validate(event)
        if parsed.kind != 33301 or parsed.pubkey != expected_author:
            raise ConcordInviteEventError("unexpected Concord invite event")
        verify_event(parsed)
        if _tag(parsed, "d") != "":
            raise ConcordInviteEventError("invite event must use an empty d coordinate")
        marker = _tag(parsed, "vsk")
        if marker == "9":
            raise ConcordInviteEventError("Concord invite has been revoked")
        if marker != "6":
            raise ConcordInviteEventError("invite event is not a live CORD-05 bundle")
        if not parsed.content:
            raise ConcordInviteEventError("invite event has empty bundle content")
        return parsed.content
    except ConcordInviteEventError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize malformed event input
        raise ConcordInviteEventError("invalid Concord invite event") from exc
