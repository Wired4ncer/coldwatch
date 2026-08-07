"""The seam between a message source and the matching loop.

Deliberately transport-agnostic: it consumes ``(topic, body, seq)`` triples, so the same code
path runs against a live SUB socket, against a recorded fixture, and against whatever a
reconciliation replay hands it. The socket wiring — two sockets, one per endpoint, because a
1.7 MB block message crowds the transaction stream — belongs to the runtime, not here.

That split is what makes the drop behaviour testable at all. `tests/fixtures/with-gap.jsonl`
replays a measured pattern of real loss with no node, no network and no timing race.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import NamedTuple

from .matcher import Match, Matcher
from .sequence import Anomaly, SequenceTracker
from .tx import MalformedTransaction, parse_tx

__all__ = ["TOPIC_BLOCK", "TOPIC_TX", "StreamIngest", "StreamMessage"]

TOPIC_TX = "rawtx"
TOPIC_BLOCK = "rawblock"


class StreamMessage(NamedTuple):
    """One ZMQ multipart message, decoded.

    ``seq`` is the third part — see `sequence.parse_seq_part`. It is not optional: a source
    that cannot supply it cannot be checked for drops, and an unchecked source is exactly
    what invariant I4 forbids trusting.
    """

    topic: str
    body: bytes
    seq: int


class StreamIngest:
    """Feeds messages through sequence tracking and the matcher.

    Counters rather than log lines, because the interesting quantities here are rates. A
    caller that wants to *announce* something passes ``on_anomaly``; nothing is swallowed.
    """

    def __init__(
        self,
        matcher: Matcher,
        tracker: SequenceTracker | None = None,
        on_anomaly: Callable[[Anomaly], None] | None = None,
    ) -> None:
        self.matcher = matcher
        self.tracker = tracker if tracker is not None else SequenceTracker()
        self._on_anomaly = on_anomaly
        self.parsed = 0
        self.malformed = 0
        self.ignored = 0
        """Messages on topics this ingest does not decode. Their sequence numbers are still
        tracked — a gap in the block stream matters even before blocks are handled."""

    def handle(self, message: StreamMessage) -> tuple[Match, ...]:
        """Process one message. Never raises on bad payload bytes.

        A single unparseable transaction must not take the loop down: the cost of skipping
        one is a missed alert on one transaction, and the cost of crashing is a missed alert
        on all of them until someone notices. It is counted, not swallowed — and a gap is
        already the standing reason reconciliation exists to catch what the stream missed.
        """
        anomaly = self.tracker.observe(message.topic, message.seq)
        if anomaly is not None and self._on_anomaly is not None:
            self._on_anomaly(anomaly)

        if message.topic != TOPIC_TX:
            self.ignored += 1
            return ()

        try:
            tx = parse_tx(message.body)
        except MalformedTransaction:
            self.malformed += 1
            return ()

        self.parsed += 1
        return self.matcher.process(tx)

    def run(self, messages: Iterable[StreamMessage]) -> list[Match]:
        """Drain a finite source, collecting matches. For fixtures and replays."""
        matches: list[Match] = []
        for message in messages:
            matches.extend(self.handle(message))
        return matches
