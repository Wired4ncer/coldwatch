"""The live end: two SUB sockets, drained into the matching loop.

Everything under `match/` is transport-agnostic and runs against fixtures with no network at
all. This is the module that gives up that property, so it is deliberately thin — decode a
multipart message, hand it over, and nothing else. Anything that can be decided without a
socket has already been decided somewhere else.

**Two sockets, one per endpoint, and this is not tidiness.** A block message is ~1.7 MB. Sharing
one socket with the transaction stream means a block sits in front of thousands of transactions
in the same queue, and the queue is bounded — so the sharing is itself a cause of the drops the
whole design is braced against.

## What the receive buffer can and cannot do

`RCVHWM` is our side of the buffer, and raising it is worth doing. It does **not** make the
stream reliable, and it is easy to believe otherwise:

* bitcoind drops at **its** high-water mark, before the bytes ever reach us — that is a node
  setting, not a client one (see issue #25). A message dropped there cannot be recovered by any
  amount of buffer here.
* ZMQ discards silently at either end. No error, no log, and the messages that do arrive look
  perfectly normal. The 4-byte sequence counter is the only evidence there is.

So the buffer reduces loss; the sequence tracker notices it; and repair is what fixes it.

## Reconnects are a gap, and are meant to be

ZMQ reconnects on its own, which is convenient and slightly dangerous: the socket comes back
with no indication that anything was missed. What arrives is a sequence counter that jumped, or
one that went backwards if bitcoind itself restarted — both of which the tracker reports and
both of which demand reconciliation.

A **fresh** subscriber is the one case nothing here can cover. The first message on a topic
establishes a baseline, so a service starting up cannot know what happened while it was not
listening. That hole is the enrolment baseline scan's, and the chain follower's for blocks; it
is not one a subscriber can close by trying harder.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Self

import zmq

from .match import Match, StreamIngest, StreamMessage
from .match.sequence import parse_seq_part

__all__ = ["DEFAULT_RCVHWM", "Subscriber"]

#: Our receive buffer, per socket. Well above the ZMQ default of 1000, because the cost is
#: memory we have and the cost of the default is a missed alert. See the module docstring for
#: what this cannot do — the publisher's high-water mark is the other half, and it is the half
#: the measured loss came from.
DEFAULT_RCVHWM = 50_000

#: How long a poll waits before looking up. Only a ceiling on how long `stop()` takes to be
#: noticed; a message that arrives wakes the poller immediately.
DEFAULT_POLL_MS = 250

TOPIC_PARTS = 3
"""topic, payload, 4-byte little-endian counter. A publisher sending fewer is one we cannot
check for drops, and an unchecked source is what invariant I4 forbids trusting."""


class Subscriber:
    """Subscribes to one node's `rawtx` and `rawblock` endpoints and feeds `StreamIngest`.

    Owns its context and sockets, and closes both — a leaked context makes a process hang on
    exit, which in a service that is supposed to be restarted by systemd is its own outage.
    """

    def __init__(
        self,
        ingest: StreamIngest,
        tx_endpoint: str,
        block_endpoint: str,
        *,
        rcvhwm: int = DEFAULT_RCVHWM,
        poll_ms: int = DEFAULT_POLL_MS,
    ) -> None:
        self.ingest = ingest
        self.poll_ms = poll_ms
        self._stopping = threading.Event()
        self._context = zmq.Context()
        self._tx = self._socket(tx_endpoint, b"rawtx", rcvhwm)
        self._block = self._socket(block_endpoint, b"rawblock", rcvhwm)
        self._poller = zmq.Poller()
        self._poller.register(self._tx, zmq.POLLIN)
        self._poller.register(self._block, zmq.POLLIN)
        self.malformed_envelopes = 0
        """Messages that did not arrive as three parts. Counted rather than raised: one
        undecodable envelope must not take down the loop that is watching everything else."""

    def _socket(self, endpoint: str, topic: bytes, rcvhwm: int):
        socket = self._context.socket(zmq.SUB)
        # Before connect: an option set afterwards may not apply to the connection that is
        # already being established, and a subscription set late silently misses messages.
        socket.setsockopt(zmq.RCVHWM, rcvhwm)
        socket.setsockopt(zmq.SUBSCRIBE, topic)
        socket.connect(endpoint)
        return socket

    def poll_once(self, on_match: Callable[[tuple[Match, ...]], None] | None = None) -> int:
        """Drain whatever is ready right now. Returns how many messages were handled.

        Both sockets are drained on every pass rather than one message at a time, so a burst on
        one topic cannot starve the other — and the block socket is drained first, because a
        block is what writes the record and a transaction only alerts.
        """
        ready = dict(self._poller.poll(self.poll_ms))
        handled = 0
        for socket in (self._block, self._tx):
            while ready.get(socket) == zmq.POLLIN:
                message = self._receive(socket)
                if message is not None:
                    matches = self.ingest.handle(message)
                    if matches and on_match is not None:
                        on_match(matches)
                handled += 1
                # Anything else already queued on this socket, without waiting again.
                ready[socket] = socket.poll(0)
        return handled

    def run(self, on_match: Callable[[tuple[Match, ...]], None] | None = None) -> None:
        """Drain until `stop()`. The service's main loop."""
        self._stopping.clear()
        while not self._stopping.is_set():
            self.poll_once(on_match)

    def stop(self) -> None:
        """Ask `run` to return. Safe from another thread, and safe to call twice."""
        self._stopping.set()

    def close(self) -> None:
        self._poller.unregister(self._tx)
        self._poller.unregister(self._block)
        for socket in (self._tx, self._block):
            socket.close(linger=0)
        self._context.term()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
        self.close()

    def _receive(self, socket) -> StreamMessage | None:
        """One multipart message, decoded. None if it was not one we can check."""
        parts = socket.recv_multipart()
        if len(parts) != TOPIC_PARTS:
            self.malformed_envelopes += 1
            return None
        topic, body, seq = parts
        try:
            return StreamMessage(topic=topic.decode("ascii"), body=body, seq=parse_seq_part(seq))
        except (UnicodeDecodeError, ValueError):
            self.malformed_envelopes += 1
            return None
