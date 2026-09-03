from __future__ import annotations

import time

import pytest

from tests.auth_helpers import make_nip98_authorization_header, new_keypair
from yunohost_mcp.auth.nip98 import Nip98Error, verify_nip98_request
from yunohost_mcp.auth.replay import ReplayCache

URL = "https://mcp.example.com/mcp"


def test_valid_get_request_verifies():
    sk, pubkey = new_keypair()
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    identity = verify_nip98_request(
        authorization_header=header,
        method="GET",
        url=URL,
        body=b"",
        replay_cache=ReplayCache(),
    )
    assert identity.pubkey == pubkey


def test_valid_post_request_with_payload_verifies():
    sk, pubkey = new_keypair()
    body = b'{"jsonrpc":"2.0","method":"tools/list"}'
    header = make_nip98_authorization_header(sk, pubkey, method="POST", url=URL, body=body)
    identity = verify_nip98_request(
        authorization_header=header,
        method="POST",
        url=URL,
        body=body,
        replay_cache=ReplayCache(),
    )
    assert identity.pubkey == pubkey


def test_missing_header_rejected():
    with pytest.raises(Nip98Error, match="missing Authorization"):
        verify_nip98_request(
            authorization_header=None,
            method="GET",
            url=URL,
            body=b"",
            replay_cache=ReplayCache(),
        )


def test_wrong_url_rejected():
    sk, pubkey = new_keypair()
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    with pytest.raises(Nip98Error, match="'u' tag"):
        verify_nip98_request(
            authorization_header=header,
            method="GET",
            url="https://mcp.example.com/other",
            body=b"",
            replay_cache=ReplayCache(),
        )


def test_wrong_method_rejected():
    sk, pubkey = new_keypair()
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    with pytest.raises(Nip98Error, match="'method' tag"):
        verify_nip98_request(
            authorization_header=header,
            method="POST",
            url=URL,
            body=b"",
            replay_cache=ReplayCache(),
        )


def test_tampered_body_rejected():
    sk, pubkey = new_keypair()
    header = make_nip98_authorization_header(sk, pubkey, method="POST", url=URL, body=b"original")
    with pytest.raises(Nip98Error, match="payload"):
        verify_nip98_request(
            authorization_header=header,
            method="POST",
            url=URL,
            body=b"tampered",
            replay_cache=ReplayCache(),
        )


def test_stale_timestamp_rejected():
    sk, pubkey = new_keypair()
    old = int(time.time()) - 3600
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL, created_at=old)
    with pytest.raises(Nip98Error, match="clock skew"):
        verify_nip98_request(
            authorization_header=header,
            method="GET",
            url=URL,
            body=b"",
            replay_cache=ReplayCache(),
        )


def test_replayed_event_rejected():
    sk, pubkey = new_keypair()
    header = make_nip98_authorization_header(sk, pubkey, method="GET", url=URL)
    cache = ReplayCache()
    verify_nip98_request(
        authorization_header=header, method="GET", url=URL, body=b"", replay_cache=cache
    )
    with pytest.raises(Nip98Error, match="already used"):
        verify_nip98_request(
            authorization_header=header, method="GET", url=URL, body=b"", replay_cache=cache
        )


def test_wrong_kind_rejected():
    sk, pubkey = new_keypair()
    from tests.auth_helpers import sign_event
    import base64
    import json

    event = sign_event(
        sk, pubkey=pubkey, created_at=int(time.time()), kind=1, tags=[["u", URL], ["method", "GET"]]
    )
    header = f"Nostr {base64.b64encode(json.dumps(event.model_dump()).encode()).decode()}"
    with pytest.raises(Nip98Error, match="expected kind"):
        verify_nip98_request(
            authorization_header=header, method="GET", url=URL, body=b"", replay_cache=ReplayCache()
        )
