"""The matching loop, and what happens to it when the stream drops a message.

Two things are being proved here. The ordinary one: a payment to a watched script is seen, the
resulting coin is tracked, and spending it raises the alarm. The uncomfortable one, in the last
section: **a dropped funding transaction disarms the alarm on the spend that follows it**, and
no amount of care in this module can fix that — only reconciliation can. That test is written
to fail if reconciliation ever makes it obsolete, which is the point.
"""

from __future__ import annotations

import pytest

from coldwatch.channels import Direction
from coldwatch.match import (
    InMemoryWatchIndex,
    Match,
    Matcher,
    StreamIngest,
    StreamMessage,
    outpoint_hmac,
    parse_tx,
    spk_hmac,
)
from coldwatch.match.tx import COINBASE_VOUT, NULL_TXID
from support import PREV, build_tx, spk

COLD = spk(0xC0)
OTHER = spk(0x11)


@pytest.fixture
def index(k_match) -> InMemoryWatchIndex:
    """One item, id 1, watching one script and holding no coins yet."""
    return InMemoryWatchIndex([(1, spk_hmac(k_match, COLD))])


@pytest.fixture
def matcher(k_match, index) -> Matcher:
    return Matcher(k_match, index)


def feed(matcher: Matcher, raw: bytes) -> tuple[Match, ...]:
    return matcher.process(parse_tx(raw))


# ── incoming ────────────────────────────────────────────────────────────────────────────────


def test_a_payment_to_a_watched_script_is_seen(matcher):
    assert feed(matcher, build_tx([(PREV, 0)], [COLD])) == (Match(1, Direction.INCOMING),)


def test_an_unrelated_transaction_matches_nothing(matcher):
    assert feed(matcher, build_tx([(PREV, 0)], [OTHER, spk(0x22)])) == ()


def test_a_payment_puts_the_coin_into_the_live_set(index, matcher, k_match):
    """Without this the watch is half-blind: it would see money arrive and never see it
    leave, which is the direction that matters."""
    raw = build_tx([(PREV, 0)], [OTHER, COLD])
    feed(matcher, raw)

    expected = outpoint_hmac(k_match, parse_tx(raw).txid, 1)
    assert index.items_owning_outpoint(expected) == [1]
    assert index.outpoint_count == 1


def test_two_tenants_watching_one_script_both_match(k_match):
    """Addresses are not owned. Two people may watch the same one, and a lookup that assumed
    a single owner would alert exactly one of them."""
    index = InMemoryWatchIndex([(1, spk_hmac(k_match, COLD)), (2, spk_hmac(k_match, COLD))])
    matches = Matcher(k_match, index).process(parse_tx(build_tx([(PREV, 0)], [COLD])))
    assert matches == (Match(1, Direction.INCOMING), Match(2, Direction.INCOMING))


def test_one_transaction_paying_a_script_twice_reports_one_match(index, matcher):
    """Two outputs, one item, one notification — but both coins tracked."""
    matches = feed(matcher, build_tx([(PREV, 0)], [COLD, COLD]))
    assert matches == (Match(1, Direction.INCOMING),)
    assert index.outpoint_count == 2


# ── outgoing ────────────────────────────────────────────────────────────────────────────────


def test_spending_a_watched_coin_raises_the_alarm(index, matcher):
    funding = build_tx([(PREV, 0)], [COLD])
    feed(matcher, funding)

    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])
    assert feed(matcher, spend) == (Match(1, Direction.OUTGOING),)


def test_a_spent_coin_leaves_the_live_set(index, matcher):
    """Otherwise the set grows forever and, worse, a later transaction reusing that outpoint
    would alarm again on a coin that is long gone."""
    funding = build_tx([(PREV, 0)], [COLD])
    feed(matcher, funding)
    feed(matcher, build_tx([(parse_tx(funding).txid, 0)], [OTHER]))
    assert index.outpoint_count == 0


def test_spending_two_watched_coins_at_once_reports_one_alarm(index, matcher):
    """One transaction, one movement. Two alarms for one event is how a user learns to
    dismiss them."""
    a = build_tx([(PREV, 0)], [COLD])
    b = build_tx([(PREV, 1)], [COLD])
    feed(matcher, a)
    feed(matcher, b)

    spend = build_tx([(parse_tx(a).txid, 0), (parse_tx(b).txid, 0)], [OTHER])
    assert feed(matcher, spend) == (Match(1, Direction.OUTGOING),)


def test_an_alarm_is_reported_before_the_informational_match(index, matcher):
    """Ordering is the product: a caller draining this tuple in order sends the urgent one
    first, and outgoing alerts are the ones that go out without jitter."""
    funding = build_tx([(PREV, 0)], [COLD])
    feed(matcher, funding)

    both = build_tx([(parse_tx(funding).txid, 0)], [OTHER, COLD])
    assert feed(matcher, both) == (Match(1, Direction.OUTGOING), Match(1, Direction.INCOMING))


def test_change_returning_to_the_same_script_stays_watched(index, matcher):
    """A partial spend replaces the coin, and the replacement must be armed too.

    Asserting the set has one entry would pass even if that entry were the *spent* coin, so
    the change is actually spent and the second alarm is required.
    """
    funding = build_tx([(PREV, 0)], [COLD])
    feed(matcher, funding)

    partial = build_tx([(parse_tx(funding).txid, 0)], [OTHER, COLD])
    feed(matcher, partial)
    assert index.outpoint_count == 1

    spend_change = build_tx([(parse_tx(partial).txid, 1)], [OTHER])
    assert feed(matcher, spend_change) == (Match(1, Direction.OUTGOING),)


def test_a_coinbase_input_is_never_looked_up(matcher, k_match):
    """Its outpoint does not exist. A hit would mean the loop believed something was spent
    when nothing was."""
    index = InMemoryWatchIndex()
    index.add_outpoint(1, outpoint_hmac(k_match, NULL_TXID, COINBASE_VOUT))
    coinbase = build_tx([(NULL_TXID, COINBASE_VOUT)], [OTHER], script_sig=b"\x03\x01\x02")

    assert Matcher(k_match, index).process(parse_tx(coinbase)) == ()


def test_segwit_spends_are_matched_like_any_other(index, matcher):
    """Nearly every real spend carries a witness. If the txid were computed over the
    unstripped bytes, the funding coin would be filed under an identifier the spend never
    references — and the alarm would simply not fire."""
    funding = build_tx([(PREV, 0)], [COLD], witness=[[b"\x30" * 71, b"\x02" * 33]])
    feed(matcher, funding)

    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER], witness=[[b"\x30" * 71]])
    assert feed(matcher, spend) == (Match(1, Direction.OUTGOING),)


# ── through the stream seam ─────────────────────────────────────────────────────────────────


def messages(*raws: bytes, start: int = 1) -> list[StreamMessage]:
    return [StreamMessage("rawtx", raw, start + i) for i, raw in enumerate(raws)]


def test_ingest_runs_the_whole_path(matcher, index):
    funding = build_tx([(PREV, 0)], [COLD])
    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])

    ingest = StreamIngest(matcher)
    assert ingest.run(messages(funding, spend)) == [
        Match(1, Direction.INCOMING),
        Match(1, Direction.OUTGOING),
    ]
    assert ingest.parsed == 2
    assert ingest.tracker.needs_reconciliation is False
    # Both alerts fired, and the record was not touched by either: the coin was armed in
    # memory, which is the whole of what the mempool is allowed to do.
    assert index.outpoint_count == 0


def test_the_recorded_stream_matches_nothing_by_accident(matcher, contiguous_stream):
    """120 synthetic transactions against a watch they know nothing about. A single hit here
    would mean the comparison is not actually comparing."""
    ingest = StreamIngest(matcher)
    assert ingest.run(contiguous_stream) == []
    assert ingest.parsed == 120
    assert ingest.malformed == 0


def test_one_unparseable_message_does_not_stop_the_loop(matcher):
    """Skipping one transaction costs one missed alert. Crashing costs all of them until
    somebody notices — and it is counted, not swallowed."""
    good = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)

    assert ingest.run(messages(b"\x02\x00\x00", good)) == [Match(1, Direction.INCOMING)]
    assert (ingest.malformed, ingest.parsed) == (1, 1)


def test_other_topics_are_not_parsed_but_are_still_counted(matcher):
    """A topic this ingest does not decode. Its sequence numbers are still tracked, because a
    gap on a topic we ignore is still evidence the transport is dropping messages."""
    ingest = StreamIngest(matcher)
    ingest.handle(StreamMessage("hashblock", b"\x00" * 32, 1))
    ingest.handle(StreamMessage("hashblock", b"\x11" * 32, 3))

    assert ingest.ignored == 2
    assert ingest.malformed == 0
    assert ingest.tracker.state("hashblock").missing_total == 1


def test_an_unparseable_block_forces_a_reconciliation(matcher):
    """A skipped transaction costs one alert. A skipped *block* costs every confirmation in
    it, and blocks are the only thing that writes the record — so the record is now behind the
    chain by an unknown amount, on a stream whose sequence numbers never skipped a beat.

    Counting it and moving on would leave that condition invisible. Only reconciliation can
    put it right, so failing to parse one has to reach the reconciler.
    """
    ingest = StreamIngest(matcher)

    assert ingest.handle(StreamMessage("rawblock", b"not a block", 1)) == ()

    assert ingest.malformed == 1
    assert ingest.blocks == 0
    assert ingest.tracker.needs_reconciliation is True


def test_anomalies_reach_the_caller(matcher):
    """Invariant I5: a drop that nobody is told about is the failure this product exists to
    prevent, wearing a metric as a disguise."""
    seen = []
    ingest = StreamIngest(matcher, on_anomaly=seen.append)
    good = build_tx([(PREV, 0)], [OTHER])

    ingest.handle(StreamMessage("rawtx", good, 1))
    ingest.handle(StreamMessage("rawtx", good, 9))

    assert [a.missing for a in seen] == [7]


# ── what a dropped message actually costs ───────────────────────────────────────────────────


def test_a_dropped_funding_transaction_disarms_the_alarm_on_the_spend(matcher, index):
    """The failure invariant I4 is about, made concrete.

    The funding transaction is dropped by the stream — nothing here is broken, ZMQ simply
    discarded it at the high-water mark. The coin therefore never enters the live set, so
    when it is spent the input matches nothing and **no alarm fires**. The user is not told.

    This is why reconciliation is a v1 requirement and not later hardening: no improvement to
    the matching loop can recover an event it was never handed. What the loop *can* do is
    know it is now unreliable, which is the assertion at the end.

    ⚠️ When the reconciler lands, this test should start failing on the alarm assertion. That
    is the signal it works — rewrite it then to assert the repair, and do not simply delete it.
    """
    funding = build_tx([(PREV, 0)], [COLD])
    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])

    ingest = StreamIngest(matcher)
    ingest.handle(StreamMessage("rawtx", build_tx([(PREV, 9)], [OTHER]), 1))
    # seq 2 was the funding transaction. It never arrives.
    matches = ingest.handle(StreamMessage("rawtx", spend, 3))

    assert matches == ()
    assert index.outpoint_count == 0
    assert ingest.tracker.needs_reconciliation is True
