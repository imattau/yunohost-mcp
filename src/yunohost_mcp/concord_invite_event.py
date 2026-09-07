"""Verification of public CORD-05 invite bundle events."""

from __future__ import annotations

from dataclasses import dataclass

import bech32

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
        hrp, words = bech32.bech32_decode(value)
        if hrp != "naddr" or words is None:
            raise ValueError
        raw = bytes(bech32.convertbits(words, 5, 8, False) or [])
    except (TypeError, ValueError) as exc:
        raise ConcordInviteEventError("invalid Concord invite naddr") from exc
    fields: dict[int, bytes] = {}
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            raise ConcordInviteEventError("truncated Concord invite naddr")
        field_type, length = raw[offset], raw[offset + 1]
        offset += 2
        end = offset + length
        if end > len(raw):
            raise ConcordInviteEventError("truncated Concord invite naddr field")
        if field_type in fields:
            raise ConcordInviteEventError("duplicate Concord invite naddr field")
        fields[field_type] = raw[offset:end]
        offset = end
    if set(fields) - {0, 2, 3} or 0 not in fields or 2 not in fields or 3 not in fields:
        raise ConcordInviteEventError("incomplete Concord invite naddr")
    identifier = fields[0].decode("utf-8", errors="strict")
    author = fields[2]
    if identifier != "" or len(author) != 32 or len(fields[3]) != 4:
        raise ConcordInviteEventError("Concord invite naddr has the wrong coordinate shape")
    kind = int.from_bytes(fields[3], "big")
    if kind != 33301:
        raise ConcordInviteEventError("Concord invite naddr has the wrong event kind")
    return InviteCoordinate(author_hex=author.hex(), kind=kind, identifier=identifier)


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
