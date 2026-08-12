"""NostrChannel -- issue #3.

Uses `FakeRelay` (an in-process stand-in, see `fake_relay.py`) rather than a real relay: what
matters here is this module's own logic, not websocket-client's already-tested transport
behaviour -- the same split `test_email_channel.py` makes for smtplib.
"""

from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime

import pytest
import websocket

from coldwatch.channels import AlertKind, Direction, PrivacyClass
from coldwatch.channels.base import Alert
from coldwatch.channels.nostr import nip44
from coldwatch.channels.nostr.bech32 import encode_npub
from coldwatch.channels.nostr.channel import MissingConfig, NostrChannel
from coldwatch.channels.nostr.nip01 import pubkey_hex_from_privkey
from fake_relay import FakeRelay, RaisingConnect, make_connect

SERVICE_SK = "0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273"
RECIPIENT_SK = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45"
RECIPIENT_PK = pubkey_hex_from_privkey(RECIPIENT_SK)
RECIPIENT_NPUB = encode_npub(bytes.fromhex(RECIPIENT_PK))

RELAY_A = "wss://relay-a.example.invalid"
RELAY_B = "wss://relay-b.example.invalid"


def make_alert(**overrides) -> Alert:
    base = {
        "kind": AlertKind.MOVEMENT,
        "label": "cold-1",
        "chain": "btc",
        "direction": Direction.OUTGOING,
        "fired_at": datetime(2026, 8, 6, tzinfo=UTC),
    }
    base.update(overrides)
    return Alert(**base)


def make_channel(*, relays=(RELAY_A,), connect=None, **overrides) -> NostrChannel:
    kwargs = {"privkey": SERVICE_SK, "relays": relays, "connect": connect}
    kwargs.update(overrides)
    return NostrChannel(**kwargs)


def decrypt_wrap(wrap: dict, recipient_privkey_hex: str) -> dict:
    conv_key = nip44.get_conversation_key(recipient_privkey_hex, wrap["pubkey"])
    return json.loads(nip44.decrypt(wrap["content"], conv_key))


def decrypt_seal(seal: dict, recipient_privkey_hex: str) -> dict:
    conv_key = nip44.get_conversation_key(recipient_privkey_hex, seal["pubkey"])
    return json.loads(nip44.decrypt(seal["content"], conv_key))


# ── kind / privacy_class ─────────────────────────────────────────────────────────────────────


def test_declares_itself_e2e_private():
    """Nostr is the privacy-recommended rail -- the enrolment gate (#23) depends on this being
    honest, same as EmailChannel declaring PROVIDER_READS."""
    assert NostrChannel.kind == "nostr"
    assert NostrChannel.privacy_class is PrivacyClass.E2E_PRIVATE


def test_satisfies_the_channel_protocol():
    from coldwatch.channels.base import Channel

    relay = FakeRelay()
    assert isinstance(make_channel(connect=make_connect({RELAY_A: relay})), Channel)


# ── validate_dest ────────────────────────────────────────────────────────────────────────────


def test_validate_dest_accepts_npub_and_normalises_to_hex():
    channel = make_channel(connect=make_connect({RELAY_A: FakeRelay()}))
    assert channel.validate_dest(RECIPIENT_NPUB) == RECIPIENT_PK


def test_validate_dest_strips_whitespace():
    channel = make_channel(connect=make_connect({RELAY_A: FakeRelay()}))
    assert channel.validate_dest(f"  {RECIPIENT_NPUB}  ") == RECIPIENT_PK


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not an npub",
        RECIPIENT_PK,  # bare hex -- issue #3 says accept an npub, reject anything else
        "nsec1p0ht6p3wepe47sjrgesyn4m50m6avk2waqudu9rl324cg2c4ufesyp6rdg",  # wrong prefix
        RECIPIENT_NPUB[:-1] + ("q" if RECIPIENT_NPUB[-1] != "q" else "p"),  # bad checksum
    ],
)
def test_validate_dest_rejects_junk(raw):
    channel = make_channel(connect=make_connect({RELAY_A: FakeRelay()}))
    with pytest.raises(ValueError):
        channel.validate_dest(raw)


# ── send: success ────────────────────────────────────────────────────────────────────────────


def test_send_success():
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())

    assert result.ok is True
    assert result.retriable is False
    assert len(relay.sent) == 1
    assert relay.closed is True


def test_send_publishes_a_kind_1059_gift_wrap_with_a_p_tag_for_the_recipient():
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    channel.send(RECIPIENT_PK, make_alert())

    wrap = relay.sent[0]
    assert wrap["kind"] == 1059
    assert wrap["tags"] == [["p", RECIPIENT_PK]]
    assert "sig" in wrap and "id" in wrap


def test_wrap_pubkey_is_ephemeral_not_the_service_identity():
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    channel.send(RECIPIENT_PK, make_alert())
    wrap = relay.sent[0]
    assert wrap["pubkey"] != channel.pubkey


def test_seal_is_signed_by_the_service_identity():
    """The 'single published npub' trust anchor from issue #3: the seal (once decrypted) must
    be signed by the same key every time, so a recipient's client can recognise coldwatch."""
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    channel.send(RECIPIENT_PK, make_alert())
    wrap = relay.sent[0]
    seal = decrypt_wrap(wrap, RECIPIENT_SK)
    assert seal["pubkey"] == channel.pubkey


# ── send: no template can emit an address, amount or txid ──────────────────────────────────


FORBIDDEN_IN_BODY = (
    "address", "addr", "amount", "sats", "satoshi",
    "txid", "tx_id", "transaction", "outpoint", "script",
    "height", "block", "fee", "balance:",
)


@pytest.mark.parametrize(
    "kind,direction",
    [
        (AlertKind.MOVEMENT, Direction.OUTGOING),
        (AlertKind.MOVEMENT, Direction.INCOMING),
        (AlertKind.TEST_FIRE, None),
        (AlertKind.LOW_BALANCE, None),
        (AlertKind.WATCH_STOPPED, None),
        (AlertKind.HEARTBEAT, None),
    ],
)
def test_no_template_leaks_chain_data(kind, direction):
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    channel.send(RECIPIENT_PK, make_alert(kind=kind, direction=direction))

    wrap = relay.sent[0]
    seal = decrypt_wrap(wrap, RECIPIENT_SK)
    rumor = decrypt_seal(seal, RECIPIENT_SK)
    body = rumor["content"].lower()
    for forbidden in FORBIDDEN_IN_BODY:
        assert forbidden not in body, f"{kind}/{direction} template leaked {forbidden!r}"


def test_outgoing_movement_reads_as_an_alarm_and_incoming_does_not():
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))

    channel.send(RECIPIENT_PK, make_alert(direction=Direction.OUTGOING))
    channel.send(RECIPIENT_PK, make_alert(direction=Direction.INCOMING))

    outgoing_body = decrypt_seal(decrypt_wrap(relay.sent[0], RECIPIENT_SK), RECIPIENT_SK)["content"]
    incoming_body = decrypt_seal(decrypt_wrap(relay.sent[1], RECIPIENT_SK), RECIPIENT_SK)["content"]
    assert "has moved" in outgoing_body
    assert "received a deposit" in incoming_body


def test_movement_with_no_direction_reads_as_an_alarm_not_a_deposit_notice():
    relay = FakeRelay(ok=True)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    channel.send(RECIPIENT_PK, make_alert(direction=None))
    body = decrypt_seal(decrypt_wrap(relay.sent[0], RECIPIENT_SK), RECIPIENT_SK)["content"]
    assert "has moved" in body
    assert "received a deposit" not in body


# ── send: failure classification ────────────────────────────────────────────────────────────


def test_permanent_relay_rejection_is_not_retriable():
    relay = FakeRelay(ok=False, note="invalid: event creation date is too far off")
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is False
    assert result.retriable is False
    assert result.detail == "invalid"


def test_rate_limited_relay_rejection_is_retriable():
    relay = FakeRelay(ok=False, note="rate-limited: slow down there chief")
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is False
    assert result.retriable is True
    assert result.detail == "rate-limited"


def test_blocked_relay_rejection_is_not_retriable():
    relay = FakeRelay(ok=False, note="blocked: you are banned from posting here")
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.retriable is False
    assert result.detail == "blocked"


def test_unrecognised_rejection_prefix_defaults_to_retriable():
    relay = FakeRelay(ok=False, note="something a relay made up that isn't in NIP-01")
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.retriable is True
    assert result.detail == "rejected"


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("connection refused"),
        TimeoutError("timed out"),
        ssl.SSLError("certificate verify failed"),
        websocket.WebSocketTimeoutException("timed out waiting for OK"),
        websocket.WebSocketConnectionClosedException("connection closed"),
    ],
)
def test_transport_failures_are_retriable(error):
    relay = FakeRelay(recv_error=error)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is False
    assert result.retriable is True


def test_unreachable_relay_is_retriable():
    channel = make_channel(
        connect=make_connect({RELAY_A: RaisingConnect(ConnectionRefusedError("no route"))})
    )
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is False
    assert result.retriable is True


# ── send: multi-relay fallback ───────────────────────────────────────────────────────────────


def test_falls_through_to_a_second_relay_when_the_first_fails():
    relay_a = FakeRelay(ok=False, note="error: could not connect to the database")
    relay_b = FakeRelay(ok=True)
    channel = make_channel(
        relays=(RELAY_A, RELAY_B),
        connect=make_connect({RELAY_A: relay_a, RELAY_B: relay_b}),
    )
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is True
    assert len(relay_a.sent) == 1
    assert len(relay_b.sent) == 1


def test_stops_at_the_first_relay_that_accepts():
    relay_a = FakeRelay(ok=True)
    relay_b = FakeRelay(ok=True)
    channel = make_channel(
        relays=(RELAY_A, RELAY_B),
        connect=make_connect({RELAY_A: relay_a, RELAY_B: relay_b}),
    )
    channel.send(RECIPIENT_PK, make_alert())
    assert len(relay_a.sent) == 1
    assert len(relay_b.sent) == 0


def test_all_relays_permanently_rejecting_is_not_retriable():
    relay_a = FakeRelay(ok=False, note="blocked: banned")
    relay_b = FakeRelay(ok=False, note="invalid: bad event")
    channel = make_channel(
        relays=(RELAY_A, RELAY_B),
        connect=make_connect({RELAY_A: relay_a, RELAY_B: relay_b}),
    )
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is False
    assert result.retriable is False


def test_one_retriable_failure_among_permanent_ones_keeps_the_whole_send_retriable():
    relay_a = FakeRelay(ok=False, note="blocked: banned")
    relay_b = FakeRelay(ok=False, note="rate-limited: slow down")
    channel = make_channel(
        relays=(RELAY_A, RELAY_B),
        connect=make_connect({RELAY_A: relay_a, RELAY_B: relay_b}),
    )
    result = channel.send(RECIPIENT_PK, make_alert())
    assert result.ok is False
    assert result.retriable is True


# ── invariant: nothing sensitive ever reaches DeliveryResult.detail ────────────────────────


FORBIDDEN_IN_DETAIL = (RECIPIENT_PK, RECIPIENT_NPUB, SERVICE_SK, "has moved", "deposit")


@pytest.mark.parametrize(
    "note",
    [
        f"invalid: rejected {RECIPIENT_PK}",
        f"blocked: banned npub for {RECIPIENT_NPUB}",
        "error: something went wrong with the has moved alert",
    ],
)
def test_delivery_result_detail_never_contains_the_destination_or_content(note):
    """A relay's free-text message is attacker-controlled infrastructure we don't run --
    `_classify_note` must reduce it to a known enum word, never pass it through verbatim."""
    relay = FakeRelay(ok=False, note=note)
    channel = make_channel(connect=make_connect({RELAY_A: relay}))
    result = channel.send(RECIPIENT_PK, make_alert())
    for forbidden in FORBIDDEN_IN_DETAIL:
        assert forbidden not in result.detail


# ── construction / config ───────────────────────────────────────────────────────────────────


def test_rejects_non_wss_relays():
    with pytest.raises(ValueError):
        make_channel(relays=("ws://insecure.example.invalid",))


def test_requires_at_least_one_relay():
    with pytest.raises(MissingConfig):
        make_channel(relays=())


def test_repr_never_contains_the_private_key():
    channel = make_channel(connect=make_connect({RELAY_A: FakeRelay()}))
    assert SERVICE_SK not in repr(channel)


def test_npub_property_matches_the_pubkey():
    channel = make_channel(connect=make_connect({RELAY_A: FakeRelay()}))
    assert encode_npub(bytes.fromhex(channel.pubkey)) == channel.npub


# ── from_env / MissingConfig ─────────────────────────────────────────────────────────────────


def test_from_env_requires_relays(monkeypatch):
    monkeypatch.setenv("COLDWATCH_NOSTR_PRIVKEY", SERVICE_SK)
    monkeypatch.delenv("COLDWATCH_NOSTR_RELAYS", raising=False)
    with pytest.raises(MissingConfig, match="COLDWATCH_NOSTR_RELAYS"):
        NostrChannel.from_env()


def test_from_env_requires_a_privkey(monkeypatch):
    monkeypatch.setenv("COLDWATCH_NOSTR_RELAYS", RELAY_A)
    monkeypatch.delenv("COLDWATCH_NOSTR_PRIVKEY", raising=False)
    monkeypatch.delenv("COLDWATCH_NOSTR_PRIVKEY_FILE", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(MissingConfig):
        NostrChannel.from_env()


def test_from_env_reads_privkey_from_file(monkeypatch, tmp_path):
    privkey_file = tmp_path / "nostr-privkey"
    privkey_file.write_text(SERVICE_SK + "\n")

    monkeypatch.setenv("COLDWATCH_NOSTR_RELAYS", f"{RELAY_A}, {RELAY_B}")
    monkeypatch.setenv("COLDWATCH_NOSTR_PRIVKEY_FILE", str(privkey_file))
    monkeypatch.delenv("COLDWATCH_NOSTR_PRIVKEY", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

    channel = NostrChannel.from_env()
    assert channel.pubkey == pubkey_hex_from_privkey(SERVICE_SK)


def test_from_env_parses_comma_and_whitespace_separated_relays(monkeypatch):
    monkeypatch.setenv("COLDWATCH_NOSTR_PRIVKEY", SERVICE_SK)
    monkeypatch.setenv("COLDWATCH_NOSTR_RELAYS", f"{RELAY_A},{RELAY_B}  wss://third.example.invalid")
    channel = NostrChannel.from_env()
    assert channel._relays == (RELAY_A, RELAY_B, "wss://third.example.invalid")
