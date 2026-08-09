"""The subscriber, driven over real ZMQ sockets.

Mocking the socket here would test the mock. The whole reason this module exists is that the
transport has behaviour — bounded queues, silent discards, slow joiners, multipart framing —
and every one of those is a thing a fake would get politely wrong. So these bind a real PUB
socket on an ephemeral loopback port and publish real multipart messages at it.

The one accommodation to reality: **PUB/SUB drops messages sent before the subscription has
propagated.** That is not a bug to work around in the service — a subscriber that has just
connected genuinely has missed whatever came before — but in a test it looks like flakiness, so
`publish_until_received` repeats until the message lands.
"""

from __future__ import annotations

import struct
import threading
import time

import pytest
import zmq

from coldwatch.channels import Direction
from coldwatch.match import (
    InMemoryWatchIndex,
    Match,
    Matcher,
    StreamIngest,
    parse_tx,
    spk_hmac,
)
from coldwatch.subscribe import DEFAULT_RCVHWM, Subscriber
from support import PREV, build_block, build_tx, coinbase_tx, spk

COLD = spk(0xC0)
OTHER = spk(0x11)
TIMEOUT = 5.0


@pytest.fixture
def publisher():
    """Two PUB sockets on ephemeral ports, standing in for bitcoind's two endpoints."""
    context = zmq.Context()
    sockets = {}
    for name in ("tx", "block"):
        socket = context.socket(zmq.PUB)
        socket.bind("tcp://127.0.0.1:0")
        sockets[name] = socket
    endpoints = {
        name: socket.getsockopt(zmq.LAST_ENDPOINT).decode() for name, socket in sockets.items()
    }
    yield sockets, endpoints
    for socket in sockets.values():
        socket.close(linger=0)
    context.term()


@pytest.fixture
def index(k_match) -> InMemoryWatchIndex:
    return InMemoryWatchIndex([(1, spk_hmac(k_match, COLD))])


@pytest.fixture
def ingest(k_match, index) -> StreamIngest:
    return StreamIngest(Matcher(k_match, index))


@pytest.fixture
def subscriber(ingest, publisher):
    _, endpoints = publisher
    sub = Subscriber(ingest, endpoints["tx"], endpoints["block"], poll_ms=50)
    yield sub
    sub.stop()
    sub.close()


def send(socket, topic: bytes, body: bytes, seq: int) -> None:
    socket.send_multipart([topic, body, struct.pack("<I", seq)])


def publish_until_received(socket, topic: bytes, body: bytes, seq: int, sub: Subscriber) -> None:
    """Publish until the subscriber actually gets something, or fail the test.

    The slow-joiner problem is real behaviour, not a test artifact: a SUB socket that has just
    connected has missed whatever was published first. In the service that shows up as a
    sequence gap and is repaired; here it would just be flaky.
    """
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        send(socket, topic, body, seq)
        if sub.poll_once() > 0:
            return
    raise AssertionError(f"nothing received on {topic!r} within {TIMEOUT}s")


# ── the wire ────────────────────────────────────────────────────────────────────────────────


def test_a_transaction_on_the_live_socket_reaches_the_matcher(subscriber, publisher, index):
    sockets, _ = publisher
    matches: list[tuple[Match, ...]] = []
    funding = build_tx([(PREV, 0)], [COLD])

    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline and not matches:
        send(sockets["tx"], b"rawtx", funding, 1)
        subscriber.poll_once(matches.append)

    assert matches and matches[0] == (Match(1, Direction.INCOMING),)
    # The mempool alerted and wrote nothing, over a real socket rather than a fixture.
    assert index.outpoint_count == 0


def test_a_block_on_the_live_socket_writes_the_record(subscriber, publisher, index):
    sockets, _ = publisher
    funding = build_tx([(PREV, 0)], [COLD])
    raw = build_block([coinbase_tx(), funding])

    publish_until_received(sockets["block"], b"rawblock", raw, 1, subscriber)

    assert index.outpoint_count == 1
    assert subscriber.ingest.blocks == 1


def test_the_sequence_counter_is_read_from_the_third_part(subscriber, publisher):
    """The tripwire on the tripwire. If this part is misread, every drop goes unnoticed and
    the service believes a stream it cannot check."""
    sockets, _ = publisher
    tx = build_tx([(PREV, 0)], [OTHER])

    publish_until_received(sockets["tx"], b"rawtx", tx, 41, subscriber)
    send(sockets["tx"], b"rawtx", tx, 50)
    subscriber.poll_once()

    assert subscriber.ingest.tracker.state("rawtx").missing_total == 8
    assert subscriber.ingest.tracker.needs_reconciliation is True


def test_an_envelope_that_is_not_three_parts_is_counted_not_fatal(subscriber, publisher):
    """A publisher we cannot check for drops. Counted rather than raised, because one
    undecodable envelope must not take down the loop watching everything else."""
    sockets, _ = publisher
    tx = build_tx([(PREV, 0)], [OTHER])
    publish_until_received(sockets["tx"], b"rawtx", tx, 1, subscriber)

    sockets["tx"].send_multipart([b"rawtx", tx])  # no counter
    subscriber.poll_once()

    assert subscriber.malformed_envelopes == 1
    assert subscriber.ingest.parsed == 1  # the good one still went through


def test_topics_are_filtered_at_the_socket(subscriber, publisher):
    """Each socket subscribes to exactly one topic. A subscription of b'' would deliver
    everything on both, which is the shared-queue arrangement this design exists to avoid."""
    sockets, _ = publisher
    tx = build_tx([(PREV, 0)], [OTHER])
    publish_until_received(sockets["tx"], b"rawtx", tx, 1, subscriber)

    send(sockets["tx"], b"hashblock", b"\x00" * 32, 2)
    send(sockets["tx"], b"rawtx", tx, 2)
    subscriber.poll_once()

    assert subscriber.ingest.ignored == 0  # the hashblock message never arrived at all
    assert subscriber.ingest.parsed == 2


# ── the sockets themselves ──────────────────────────────────────────────────────────────────


def test_each_endpoint_gets_its_own_socket(subscriber):
    """A ~1.7 MB block sharing a queue with the transaction stream is itself a cause of drops.
    Two sockets is the design; asserting it is what stops a later 'simplification'."""
    assert subscriber._tx is not subscriber._block
    assert subscriber._tx.getsockopt(zmq.LAST_ENDPOINT) != subscriber._block.getsockopt(
        zmq.LAST_ENDPOINT
    )


def test_the_receive_buffer_is_raised_above_the_default(subscriber):
    """ZMQ defaults to 1000, and the default is what the measured loss was measured under.
    This cannot make the stream reliable — bitcoind drops at its own high-water mark before
    the bytes reach us (issue #25) — but it is the half we control."""
    assert subscriber._tx.getsockopt(zmq.RCVHWM) == DEFAULT_RCVHWM
    assert subscriber._block.getsockopt(zmq.RCVHWM) == DEFAULT_RCVHWM
    assert DEFAULT_RCVHWM > 1000


def test_blocks_are_drained_before_transactions(subscriber, publisher, index):
    """When both are ready, the record's writer goes first. A transaction only alerts; a block
    is the only thing that can arm a coin, and arming it first is what lets a spend published
    in the same breath be recognised."""
    sockets, _ = publisher
    funding = build_tx([(PREV, 0)], [COLD])
    spend_of_it = build_tx([(parse_tx(funding).txid, 0)], [OTHER])

    publish_until_received(sockets["block"], b"rawblock", build_block([coinbase_tx()]), 1,
                           subscriber)

    # Queue both before draining: the spend on the transaction socket, its funding in a block.
    send(sockets["tx"], b"rawtx", spend_of_it, 2)
    send(sockets["block"], b"rawblock", build_block([coinbase_tx(), funding]), 2)
    time.sleep(0.1)  # let both arrive at the subscriber before it polls

    alerts: list[tuple[Match, ...]] = []
    subscriber.poll_once(alerts.append)

    flat = [m for group in alerts for m in group]
    assert Match(1, Direction.OUTGOING) in flat, "the spend did not see its funding"


# ── lifecycle ───────────────────────────────────────────────────────────────────────────────


def test_run_returns_promptly_when_stopped(subscriber):
    """`stop()` from another thread. A service that takes longer to die than it needs to is a
    service systemd eventually kills instead, and a killed process leaves a scan running."""
    thread = threading.Thread(target=subscriber.run, daemon=True)
    thread.start()
    time.sleep(0.1)

    subscriber.stop()
    thread.join(timeout=TIMEOUT)

    assert not thread.is_alive()


def test_close_is_safe_and_leaves_no_context_running(ingest, publisher):
    """A leaked context makes the process hang on exit — which, in a service meant to be
    restarted by systemd, is its own outage."""
    _, endpoints = publisher
    with Subscriber(ingest, endpoints["tx"], endpoints["block"], poll_ms=10) as sub:
        sub.poll_once()

    assert sub._tx.closed and sub._block.closed
