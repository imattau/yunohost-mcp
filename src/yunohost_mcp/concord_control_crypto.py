"""Verification and decoding of Concord Control Plane wraps."""

from __future__ import annotations

import json

from .auth.nostr import NostrEvent, UnsignedNostrEvent, compute_event_id, verify_event
from .concord_keys import GroupKeyMaterial


class ControlPlaneError(ValueError):
    """A Control Plane wrap or its signed seal is malformed or invalid."""


def decode_control_wrap(
    wrap: dict,
    read_key: GroupKeyMaterial,
    *,
    expected_stream_pubkey: str,
    decrypt,
) -> dict:
    """Verify and decode one Control Plane wrap into an unsigned rumor.

    The caller must still apply CORD-04 roster/authority rules to the returned
    rumor. This function establishes transport integrity and authorship only.
    ``decrypt`` is called exactly once for the outer control-read ciphertext.
    """

    try:
        outer = NostrEvent.model_validate(wrap)
        if outer.kind != 1059 or outer.pubkey != expected_stream_pubkey:
            raise ControlPlaneError("unexpected Control Plane stream event")
        verify_event(outer)
        seal = NostrEvent.model_validate(json.loads(decrypt(outer.content)))
        if seal.kind != 20014:
            raise ControlPlaneError("Control Plane requires a plaintext seal")
        verify_event(seal)
        rumor = UnsignedNostrEvent.model_validate(json.loads(seal.content))
    except ControlPlaneError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize malformed/crypto input
        raise ControlPlaneError("invalid Control Plane wrap") from exc
    if rumor.pubkey != seal.pubkey or rumor.kind != 3308:
        raise ControlPlaneError("Control Plane seal does not bind its rumor")
    if rumor.id != compute_event_id(rumor):
        raise ControlPlaneError("Control Plane rumor id does not match its content")
    return rumor.model_dump()
