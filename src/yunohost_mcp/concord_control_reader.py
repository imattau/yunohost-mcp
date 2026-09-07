"""Community Control Plane acquisition for validated Concord bundles."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from .concord_bundle import ValidatedInviteBundle
from .concord_control_crypto import decode_control_wrap
from .concord_crypto import decrypt_self_conversation
from .concord_keys import derive_group_key
from .concord_transport import fetch_control_events


async def load_control_rumors(
    bundle: ValidatedInviteBundle,
    *,
    fetcher: Callable[[str, list[str]], Awaitable[list]] = fetch_control_events,
) -> list[dict]:
    """Fetch and verify Control Plane rumors for a validated community.

    A split-era bundle supplies ``control_pk``. Legacy bundles omit it and use
    the public key derived from the community read key as their stream address.
    No roster authorization is applied here; callers must pass the resulting
    rumors through an authority-aware fold before acting on control state.
    """

    read_key = derive_group_key(
        bundle.community_root,
        "concord/control",
        bytes.fromhex(bundle.community_id),
        bundle.root_epoch,
    )
    expected_stream = bundle.control_pk or read_key.pubkey_hex
    events = await fetcher(expected_stream, list(bundle.relays))
    rumors: list[dict] = []

    def decrypt(payload: str) -> str:
        return decrypt_self_conversation(read_key, payload)

    for event in events:
        if hasattr(event, "as_json"):
            event = json.loads(event.as_json())
        elif hasattr(event, "model_dump"):
            event = event.model_dump()
        if isinstance(event, dict):
            rumors.append(
                decode_control_wrap(
                    event,
                    read_key,
                    expected_stream_pubkey=expected_stream,
                    decrypt=decrypt,
                )
            )
    return rumors
