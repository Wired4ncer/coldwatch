"""Gap detection, against the measured loss pattern the fixtures encode.

The headline test is `test_gapped_stream_reports_exactly_the_measured_loss`: three gaps,
832 messages. Those numbers are not arbitrary — they are what a real node actually dropped in
a 40-minute window, with no error raised. If this test ever passes for the wrong reason, the
service goes quiet in exactly the way invariant I4 exists to prevent.
"""

from __future__ import annotations

import struct

import pytest

from coldwatch.match import AnomalyKind, SequenceTracker, StreamMessage, parse_seq_part
from coldwatch.match.sequence import UINT32, WRAP_MARGIN

TX = "rawtx"


def observe_all(tracker: SequenceTracker, messages: list[StreamMessage]) -> list:
    return [
        a
        for a in (tracker.observe(m.topic, m.seq) for m in messages)
        if a is not None
    ]


# ── the definition of done ──────────────────────────────────────────────────────────────────


def test_contiguous_stream_reports_nothing(contiguous_stream):
    """The baseline. A detector that cries wolf on a healthy stream is worse than none: it
    trains whoever reads the alerts to stop reading them."""
    tracker = SequenceTracker()
    assert observe_all(tracker, contiguous_stream) == []
    assert tracker.missing_total == 0
    assert tracker.needs_reconciliation is False
    assert tracker.state(TX).received == 120


def test_gapped_stream_reports_exactly_the_measured_loss(gapped_stream):
    """Exactly 3 gaps totalling 832 — the issue #4 definition of done."""
    tracker = SequenceTracker()
    anomalies = observe_all(tracker, gapped_stream)

    assert [a.kind for a in anomalies] == [AnomalyKind.GAP] * 3
    assert [a.missing for a in anomalies] == [599, 26, 207]
    assert tracker.missing_total == 832
    assert tracker.state(TX).gaps == 3


def test_a_gap_demands_reconciliation(gapped_stream):
    """The point of detecting a drop. The flag is the entire product of this module — a gap
    that is counted but not acted on is a missed alert with a metric attached."""
    tracker = SequenceTracker()
    observe_all(tracker, gapped_stream)
    assert tracker.needs_reconciliation is True


def test_the_flag_stays_set_until_reconciliation_actually_runs(gapped_stream):
    """Sticky across clean messages. A flag that cleared itself on the next good message
    would go quiet before anything was repaired."""
    tracker = SequenceTracker()
    observe_all(tracker, gapped_stream)
    for seq in range(1000, 1100):
        tracker.observe(TX, seq)
    assert tracker.needs_reconciliation is True

    tracker.reconciled()
    assert tracker.needs_reconciliation is False


# ── the individual behaviours ───────────────────────────────────────────────────────────────


def test_first_message_establishes_a_baseline_without_claiming_loss():
    """We cannot know what happened before we were listening, and guessing would report a
    gap on every startup. Catch-up after downtime is the block handler's job."""
    tracker = SequenceTracker()
    assert tracker.observe(TX, 5_000) is None
    assert tracker.missing_total == 0


def test_a_single_drop_is_reported():
    tracker = SequenceTracker()
    tracker.observe(TX, 1)
    anomaly = tracker.observe(TX, 3)
    assert anomaly is not None
    assert anomaly.kind is AnomalyKind.GAP
    assert (anomaly.last_seq, anomaly.seq, anomaly.missing) == (1, 3, 1)


def test_topics_are_tracked_independently():
    """Each topic has its own counter — which is also why they get their own sockets."""
    tracker = SequenceTracker()
    tracker.observe("rawtx", 100)
    tracker.observe("rawblock", 7)
    tracker.observe("rawtx", 101)
    assert tracker.observe("rawblock", 9) is not None
    assert tracker.state("rawtx").gaps == 0
    assert tracker.state("rawblock").gaps == 1
    assert tracker.missing_total == 1


def test_counter_wrap_is_not_four_billion_missing():
    """The counter is uint32 and wraps. Reading that as a gap of ~4.29 billion would bury
    the real number in every metric that sums it."""
    tracker = SequenceTracker()
    tracker.observe(TX, UINT32 - 2)
    anomaly = tracker.observe(TX, 1)
    assert anomaly is not None
    assert anomaly.kind is AnomalyKind.GAP
    assert anomaly.missing == 2  # UINT32-1 and 0


def test_a_restart_is_a_loss_of_unknown_size_not_a_gap_of_zero():
    """bitcoind restarting resets the counter. How much was missed is unknowable — which is
    why it still forces reconciliation rather than being written off as a hiccup."""
    tracker = SequenceTracker()
    tracker.observe(TX, 500_000)
    anomaly = tracker.observe(TX, 3)
    assert anomaly is not None
    assert anomaly.kind is AnomalyKind.RESTART
    assert anomaly.missing == 0
    assert tracker.missing_total == 0  # unknown, and must not be summed as zero loss
    assert tracker.needs_reconciliation is True
    assert tracker.state(TX).restarts == 1


def test_a_wrap_is_distinguished_from_a_restart_by_where_it_lands():
    """Both go backwards. Only one of them is near the ceiling beforehand."""
    tracker = SequenceTracker()
    tracker.observe(TX, UINT32 - WRAP_MARGIN - 1)
    assert tracker.observe(TX, 0).kind is AnomalyKind.RESTART


def test_a_duplicate_is_neither_loss_nor_silence():
    """Nothing was dropped, so it must not inflate the loss count — but the transport is not
    behaving as assumed, and a wrong assumption here is expensive."""
    tracker = SequenceTracker()
    tracker.observe(TX, 42)
    anomaly = tracker.observe(TX, 42)
    assert anomaly is not None
    assert anomaly.kind is AnomalyKind.DUPLICATE
    assert anomaly.missing == 0
    assert tracker.missing_total == 0
    assert tracker.needs_reconciliation is False


def test_reading_an_unseen_topic_does_not_invent_it():
    """A metrics scrape must not create topics that never published anything."""
    tracker = SequenceTracker()
    assert tracker.state("rawblock").received == 0
    assert tracker.topics == ()


@pytest.mark.parametrize("bad", [-1, UINT32, UINT32 + 1])
def test_out_of_range_sequence_numbers_are_rejected(bad):
    with pytest.raises(ValueError):
        SequenceTracker().observe(TX, bad)


# ── the wire format ─────────────────────────────────────────────────────────────────────────


def test_seq_part_is_little_endian():
    """The third ZMQ part. Big-endian would turn every counter into a nonsense number, and
    the symptom would be a gap alert on literally every message."""
    assert parse_seq_part(struct.pack("<I", 305_419_896)) == 305_419_896
    assert parse_seq_part(b"\x01\x00\x00\x00") == 1


@pytest.mark.parametrize("bad", [b"", b"\x01", b"\x01\x00\x00", b"\x00" * 5])
def test_seq_part_must_be_four_bytes(bad):
    with pytest.raises(ValueError):
        parse_seq_part(bad)
