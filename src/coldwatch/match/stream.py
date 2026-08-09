"""The seam between a message source and the matching loop.

Deliberately transport-agnostic: it consumes ``(topic, body, seq)`` triples, so the same code
path runs against a live SUB socket, against a recorded fixture, and against whatever a
reconciliation replay hands it. The socket wiring — two sockets, one per endpoint, because a
1.7 MB block message crowds the transaction stream — belongs to the runtime, not here.

That split is what makes the drop behaviour testable at all. `tests/fixtures/with-gap.jsonl`
replays a measured pattern of real loss with no node, no network and no timing race.

The two topics are **not** two ways of learning the same thing:

* ``rawtx`` alerts. It never writes to the record.
* ``rawblock`` writes. It is the only thing that does.

Why, in one line: `scantxoutset` reports confirmed state, so a record written on first sight
would make an unconfirmed receipt indistinguishable from a missed spend and reconciliation
could no longer tell a repair from a false alarm. The full argument is docs/architecture.md §4.

The cost of that rule is that every transaction is seen twice, and must alert once — hence the
seen-set below.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable
from typing import NamedTuple

from .block import MalformedBlock, parse_block
from .matcher import Match, Matcher
from .sequence import Anomaly, SequenceTracker
from .tx import MalformedTransaction, parse_tx

__all__ = ["TOPIC_BLOCK", "TOPIC_TX", "SeenTransactions", "StreamIngest", "StreamMessage"]

TOPIC_TX = "rawtx"
TOPIC_BLOCK = "rawblock"

#: How many txids to remember for de-duplication. Only transactions that actually *matched* are
#: remembered — an alert is the only thing there is to suppress — so this counts alerts, not
#: traffic, and a service seeing 200k of them before the first one confirms has a different
#: problem. Overflowing degrades into a duplicate alert, never a missed one.
DEFAULT_SEEN_MAX = 200_000


class StreamMessage(NamedTuple):
    """One ZMQ multipart message, decoded.

    ``seq`` is the third part — see `sequence.parse_seq_part`. It is not optional: a source
    that cannot supply it cannot be checked for drops, and an unchecked source is exactly
    what invariant I4 forbids trusting.
    """

    topic: str
    body: bytes
    seq: int


class SeenTransactions:
    """Txids already alerted on, so a confirmation does not repeat what the mempool said.

    **In memory only, and it must stay that way.** Persisting "this txid was seen at this time"
    would put a timestamp beside a chain event at rest, which is precisely the correlation
    HMAC-at-rest exists to prevent (DESIGN §3b) — the record would become the event history the
    privacy review removed.

    The consequence is accepted and is the right way round: after a restart, a transaction
    caught between the mempool and its block alerts twice. A duplicate alert is noise; a missed
    one is the failure this product exists to prevent.
    """

    def __init__(self, maxlen: int = DEFAULT_SEEN_MAX) -> None:
        if maxlen < 1:
            raise ValueError("seen-set bound must be at least 1")
        self.maxlen = maxlen
        self._seen: OrderedDict[bytes, None] = OrderedDict()
        self.evicted = 0
        """Txids forgotten before their block arrived. A non-zero count here is the only
        warning that duplicate alerts are being caused by the bound rather than by a restart.

        It should stay at zero: only matching transactions are ever added, so reaching the
        bound means either an implausible flood of real alerts or a bug adding non-matches."""

    def add(self, txid: bytes) -> bool:
        """Remember a txid. False if it was already known.

        Insertion order, not access order: a txid that arrives twice keeps its original
        position, because what the bound is protecting against is age, not unpopularity.
        """
        if txid in self._seen:
            return False
        self._seen[txid] = None
        while len(self._seen) > self.maxlen:
            self._seen.popitem(last=False)
            self.evicted += 1
        return True

    def __contains__(self, txid: object) -> bool:
        return txid in self._seen

    def __len__(self) -> int:
        return len(self._seen)


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
        seen: SeenTransactions | None = None,
    ) -> None:
        self.matcher = matcher
        self.tracker = tracker if tracker is not None else SequenceTracker()
        self.seen = seen if seen is not None else SeenTransactions()
        self._on_anomaly = on_anomaly
        self.parsed = 0
        self.malformed = 0
        self.ignored = 0
        """Messages on topics this ingest does not decode. Their sequence numbers are still
        tracked — a gap in the block stream matters even before blocks are handled."""
        self.blocks = 0
        self.confirmed = 0
        """Transactions folded into the record. The record's write count, and the only one."""
        self.suppressed = 0
        """Confirmations whose alert the mempool already sent. Expected to be most of them —
        a number near zero means the transaction stream is not arriving."""

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

        if message.topic == TOPIC_TX:
            return self._handle_tx(message.body)
        if message.topic == TOPIC_BLOCK:
            return self._handle_block(message.body)

        self.ignored += 1
        return ()

    def _handle_tx(self, body: bytes) -> tuple[Match, ...]:
        """Mempool: alert, touch nothing."""
        try:
            tx = parse_tx(body)
        except MalformedTransaction:
            self.malformed += 1
            return ()

        self.parsed += 1
        matches = self.matcher.match(tx)
        # Arm what it pays to a watched script, in memory. Without this, a deposit spent again
        # before it confirms would never be armed at all and the spend would alarm nobody.
        self.matcher.note_unconfirmed(tx)
        if matches and not self.seen.add(tx.txid):
            return ()  # already alerted — a duplicate publication, or a re-broadcast
        return matches

    def _handle_block(self, body: bytes) -> tuple[Match, ...]:
        """Confirmation: fold every transaction into the record, alert on what is new.

        Matching and applying alternate per transaction rather than in two passes, so a coin
        that arrives and is spent again inside the same block is seen doing both.
        """
        try:
            block = parse_block(body)
        except MalformedBlock:
            self.malformed += 1
            # Not just a counter. Under the write rule this block was the record's only chance
            # to learn about every transaction in it, so the record is now behind the chain by
            # an unknown amount — which is the exact condition reconciliation repairs.
            self.tracker.flag_for_reconciliation()
            return ()

        self.blocks += 1
        alerts: list[Match] = []
        for tx in block.transactions:
            matches = self.matcher.match(tx)
            self.matcher.apply(tx)
            self.confirmed += 1
            if not matches:
                continue
            if self.seen.add(tx.txid):
                alerts.extend(matches)
            else:
                self.suppressed += 1
        return tuple(alerts)

    def run(self, messages: Iterable[StreamMessage]) -> list[Match]:
        """Drain a finite source, collecting matches. For fixtures and replays."""
        matches: list[Match] = []
        for message in messages:
            matches.extend(self.handle(message))
        return matches
