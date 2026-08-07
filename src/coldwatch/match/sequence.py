"""Sequence tracking: the only in-band evidence that the firehose dropped something.

ZMQ discards at the high-water mark. It does not raise, it does not log, and the payloads
that do arrive look perfectly normal — measured against the real node, **~832 transactions
vanished across 3 gaps in a 40-minute window** with no error of any kind. A dropped
transaction is a missed alert, which is the single failure this product exists to prevent.

So the counter in the third message part is not diagnostics. It is the tripwire on the
tripwire, and it exists to answer one question: *does the UTXO set need re-checking?*

Detecting a gap does not repair it — :attr:`SequenceTracker.needs_reconciliation` is the seam
where repair gets triggered. Correctness comes from reconciliation; this module only decides
when to ask for it (invariant I4).
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "Anomaly",
    "AnomalyKind",
    "SequenceTracker",
    "TopicState",
    "parse_seq_part",
]

UINT32 = 1 << 32

#: A counter that jumps backwards is either a wrap or a publisher restart. Treat it as a wrap
#: only when it looks like one: near the ceiling before, near the floor after. A drop of more
#: than 65,536 messages *at the exact moment the counter wraps* would be misread — but the two
#: readings differ only in the number reported, not in what happens next, because both demand
#: reconciliation anyway.
WRAP_MARGIN = 1 << 16


class AnomalyKind(Enum):
    GAP = "gap"
    """Messages were dropped. The count is known exactly."""

    RESTART = "restart"
    """The counter went backwards implausibly far — bitcoind restarted and reset it. How much
    was missed is unknowable, which is precisely why it must be treated as a loss."""

    DUPLICATE = "duplicate"
    """The same sequence number twice. Nothing was lost; worth counting because it means an
    assumption about the transport is wrong, and a wrong assumption here is expensive."""


@dataclass(frozen=True)
class Anomaly:
    topic: str
    kind: AnomalyKind
    last_seq: int
    seq: int
    missing: int
    """Exact for a gap. Zero for a duplicate, and zero for a restart — where it means
    *unknown*, not *none*. Never sum this as though it were a complete loss count."""


@dataclass
class TopicState:
    """Per-topic counters. One state per topic, because each has its own counter — which is
    also why the two topics get their own sockets: a 1.7 MB block message sharing a socket
    with the transaction stream is itself a cause of drops."""

    last_seq: int | None = None
    received: int = 0
    missing_total: int = 0
    gaps: int = 0
    restarts: int = 0
    duplicates: int = 0


def parse_seq_part(part: bytes) -> int:
    """Decode the third ZMQ message part: a 4-byte little-endian counter."""
    if len(part) != 4:
        raise ValueError("sequence part must be 4 bytes")
    return struct.unpack("<I", part)[0]


class SequenceTracker:
    """Tracks per-topic message continuity and flags when the record needs re-checking."""

    def __init__(self) -> None:
        self._topics: dict[str, TopicState] = defaultdict(TopicState)
        self._needs_reconciliation = False

    def observe(self, topic: str, seq: int) -> Anomaly | None:
        """Record one message. Returns an anomaly if this one did not follow the last.

        The first message on a topic establishes the baseline and reports nothing — we cannot
        know what happened before we were listening. Startup catch-up is the block handler's
        job, not this one's.
        """
        if not 0 <= seq < UINT32:
            raise ValueError("sequence number out of range")

        state = self._topics[topic]
        last = state.last_seq
        state.received += 1
        state.last_seq = seq

        if last is None:
            return None

        delta = seq - last
        if delta == 1:
            return None

        if delta == 0:
            state.duplicates += 1
            return Anomaly(topic, AnomalyKind.DUPLICATE, last, seq, 0)

        if delta > 1:
            missing = delta - 1
        elif last >= UINT32 - WRAP_MARGIN and seq < WRAP_MARGIN:
            missing = (seq + UINT32 - last) - 1
        else:
            state.restarts += 1
            self._needs_reconciliation = True
            return Anomaly(topic, AnomalyKind.RESTART, last, seq, 0)

        state.gaps += 1
        state.missing_total += missing
        self._needs_reconciliation = True
        return Anomaly(topic, AnomalyKind.GAP, last, seq, missing)

    def state(self, topic: str) -> TopicState:
        """Counters for one topic. Reading an unseen topic does not create it — otherwise a
        metrics scrape would invent topics that never published anything."""
        return self._topics.get(topic, TopicState())

    @property
    def topics(self) -> tuple[str, ...]:
        return tuple(self._topics)

    @property
    def missing_total(self) -> int:
        """Across every topic. Excludes restarts, whose loss is unknown by definition."""
        return sum(s.missing_total for s in self._topics.values())

    @property
    def needs_reconciliation(self) -> bool:
        """Set by any loss; cleared only by :meth:`reconciled`.

        ⚠️ Sticky on purpose. A flag that resets itself on the next clean message would go
        quiet before anything had actually been repaired, which is the failure this whole
        module exists to make impossible.
        """
        return self._needs_reconciliation

    def reconciled(self) -> None:
        """Called by the reconciler *after* a successful pass over the UTXO set.

        Not before. Clearing this on the attempt rather than the result would turn a failing
        reconciler into a silent one — invariant I5.
        """
        self._needs_reconciliation = False
