import pytest
from nostr_sdk import Keys, SecretKey
from nostr_sdk import ReqTarget

from yunohost_mcp.auth.nostr import sign_event
from yunohost_mcp.concord_transport import fetch_control_events, fetch_invite_events, publish_signed_event


class FakeClient:
    instances = []

    def __init__(self):
        self.relays = []
        self.connected = False
        self.sent = []
        self.shutdown_called = False
        self.fetched = False
        self.fetch_target = None
        self.__class__.instances.append(self)

    async def add_relay(self, relay):
        self.relays.append(str(relay))

    async def connect(self):
        self.connected = True

    async def send_event(self, event):
        self.sent.append(event)

    async def shutdown(self):
        self.shutdown_called = True

    async def fetch_events(self, filter_, *, timeout, max_events):
        self.fetched = True
        self.fetch_target = filter_
        return ["invite-event"] if max_events == 1 else ["control-event"]


@pytest.mark.anyio
async def test_publish_signed_event_deduplicates_relays_and_shuts_down():
    FakeClient.instances.clear()
    key = Keys(SecretKey.from_bytes(b"a" * 32))
    pubkey = key.public_key().to_hex()
    event = sign_event(key, pubkey=pubkey, kind=1059, tags=[], content="ciphertext", created_at=1)

    result = await publish_signed_event(
        event,
        ["wss://relay.example", " wss://relay.example ", "wss://other.example"],
        client_factory=FakeClient,
    )

    client = FakeClient.instances[0]
    assert result.event_id == event.id
    assert result.relays == ("wss://relay.example", "wss://other.example")
    assert client.connected is True
    assert len(client.sent) == 1
    assert client.shutdown_called is True


@pytest.mark.anyio
async def test_publish_signed_event_rejects_missing_relays():
    key = Keys(SecretKey.from_bytes(b"a" * 32))
    pubkey = key.public_key().to_hex()
    event = sign_event(key, pubkey=pubkey, kind=1059, tags=[], content="ciphertext", created_at=1)

    with pytest.raises(ValueError, match="at least one"):
        await publish_signed_event(event, [])


@pytest.mark.anyio
async def test_fetch_control_events_is_bounded_and_shuts_down():
    FakeClient.instances.clear()
    key = Keys(SecretKey.from_bytes(b"a" * 32))
    pubkey = key.public_key().to_hex()

    events = await fetch_control_events(pubkey, ["wss://relay.example"], max_events=4, client_factory=FakeClient)

    client = FakeClient.instances[0]
    assert events == ["control-event"]
    assert client.fetched is True
    assert isinstance(client.fetch_target, ReqTarget)
    assert client.shutdown_called is True


@pytest.mark.anyio
async def test_fetch_control_events_rejects_invalid_control_key():
    with pytest.raises(ValueError, match="public key"):
        await fetch_control_events("not-a-key", ["wss://relay.example"])


@pytest.mark.anyio
async def test_fetch_invite_events_uses_single_addressable_coordinate_result():
    FakeClient.instances.clear()
    key = Keys(SecretKey.from_bytes(b"a" * 32))
    pubkey = key.public_key().to_hex()

    events = await fetch_invite_events(pubkey, ["wss://relay.example"], client_factory=FakeClient)

    assert events == ["invite-event"]
    assert isinstance(FakeClient.instances[0].fetch_target, ReqTarget)
    assert FakeClient.instances[0].shutdown_called is True
