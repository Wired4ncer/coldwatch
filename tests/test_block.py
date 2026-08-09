"""Block parsing, and the rule that only a block may write.

The rule is the subject here, not the parser. `rawtx` alerts and touches nothing; `rawblock`
alerts and is the only thing that mutates the record. Every test below is a way of asking
whether that separation actually holds, because the moment it stops holding, reconciliation
starts reading unconfirmed receipts as missed spends — a false alarm on the one signal this
service exists to produce (docs/architecture.md §4).
"""

from __future__ import annotations

import pytest

from coldwatch.channels import Direction
from coldwatch.match import (
    InMemoryWatchIndex,
    MalformedBlock,
    Match,
    Matcher,
    SeenTransactions,
    StreamIngest,
    StreamMessage,
    outpoint_hmac,
    parse_block,
    parse_tx,
    spk_hmac,
)
from support import PREV, build_block, build_tx, coinbase_tx, dsha256, spk

COLD = spk(0xC0)
OTHER = spk(0x11)


@pytest.fixture
def index(k_match) -> InMemoryWatchIndex:
    return InMemoryWatchIndex([(1, spk_hmac(k_match, COLD))])


@pytest.fixture
def matcher(k_match, index) -> Matcher:
    return Matcher(k_match, index)


def tx_msg(raw: bytes, seq: int) -> StreamMessage:
    return StreamMessage("rawtx", raw, seq)


def block_msg(txs: list[bytes], seq: int, prev: bytes = PREV) -> StreamMessage:
    return StreamMessage("rawblock", build_block(txs, prev=prev), seq)


# ── the parser ──────────────────────────────────────────────────────────────────────────────


def test_a_block_yields_its_transactions_in_order():
    txs = [coinbase_tx(), build_tx([(PREV, 0)], [COLD]), build_tx([(PREV, 1)], [OTHER])]

    block = parse_block(build_block(txs))

    assert [t.txid for t in block.transactions] == [parse_tx(t).txid for t in txs]
    assert block.transactions[0].is_coinbase is True


def test_the_block_hash_is_the_header_hash_and_the_parent_is_carried():
    """Reconciliation anchors its diff to a `bestblock`, so the identity of a block and the
    identity of its parent are both load-bearing — a tip that moved on and a tip that moved
    sideways are different situations."""
    raw = build_block([coinbase_tx()], prev=bytes(range(32)))

    block = parse_block(raw)

    assert block.block_hash == dsha256(raw[:80])
    assert block.prev_hash == bytes(range(32))


def test_back_to_back_transactions_are_split_at_the_right_offsets():
    """Nothing in a block delimits its transactions. The second one is found only by having
    parsed the first exactly, so a parser that is off by a byte does not fail — it silently
    reports different transactions from the ones in the block."""
    segwit = build_tx([(PREV, 0)], [COLD], witness=[[b"\x30" * 71, b"\x02" * 33]])
    legacy = build_tx([(PREV, 1)], [OTHER])

    block = parse_block(build_block([coinbase_tx(), segwit, legacy]))

    assert len(block.transactions) == 3
    assert block.transactions[1].txid == parse_tx(segwit).txid
    assert block.transactions[1].has_witness is True
    assert block.transactions[2].txid == parse_tx(legacy).txid


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        (b"", "empty"),
        (b"\x00" * 40, "shorter than a header"),
        (b"\x00" * 80 + b"\x00", "claims no transactions"),
        (b"\x00" * 80 + b"\x01" + b"\x02\x00\x00", "transaction is truncated"),
        (b"\x00" * 80 + b"\xff" + b"\xff" * 8, "count exceeds what is there"),
    ],
)
def test_a_block_that_cannot_be_parsed_is_refused_whole(raw: bytes, why: str):
    """Never partially. Half a block applied to the record is a state no chain ever had, and
    from the outside it looks exactly like a correctly applied one."""
    with pytest.raises(MalformedBlock):
        parse_block(raw)


def test_a_block_cut_short_is_refused_rather_than_returned_as_the_part_that_parsed():
    """A truncated block: the count says three transactions, only two arrived.

    This is the case a trailing-bytes check cannot catch — the bytes present are consumed
    exactly, so everything lines up and the only evidence of loss is the count. Skipping the
    transaction that will not parse would return a block that looks complete and is missing a
    third of its confirmations, which under the write rule is the record silently falling
    behind the chain.
    """
    txs = [coinbase_tx(), build_tx([(PREV, 0)], [COLD] * 8), build_tx([(PREV, 1)], [OTHER] * 8)]

    with pytest.raises(MalformedBlock):
        parse_block(build_block(txs, count=len(txs) + 1))


def test_trailing_bytes_are_refused_rather_than_ignored():
    """Trailing bytes mean the count was wrong or a transaction was misparsed. Either way the
    transactions just read are not trustworthy as a set, even the ones that parsed cleanly."""
    with pytest.raises(MalformedBlock):
        parse_block(build_block([coinbase_tx()]) + b"\x00\x01\x02")


# ── the write rule ──────────────────────────────────────────────────────────────────────────


def test_a_mempool_payment_alerts_without_writing_the_record(matcher, index):
    ingest = StreamIngest(matcher)
    funding = build_tx([(PREV, 0)], [COLD])

    assert ingest.handle(tx_msg(funding, 1)) == (Match(1, Direction.INCOMING),)
    assert index.outpoint_count == 0
    assert ingest.confirmed == 0


def test_the_block_writes_it(matcher, index, k_match):
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)
    ingest.handle(tx_msg(funding, 1))

    ingest.handle(block_msg([coinbase_tx(), funding], 1))

    expected = outpoint_hmac(k_match, parse_tx(funding).txid, 0)
    assert index.items_owning_outpoint(expected) == [1]
    assert (ingest.blocks, ingest.confirmed) == (1, 2)


def test_a_confirmation_does_not_alert_twice(matcher):
    """The same transaction is seen twice by design — once in the mempool, once in a block.
    Alerting twice for one movement is how a user learns to ignore the alerts."""
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)

    first = ingest.handle(tx_msg(funding, 1))
    second = ingest.handle(block_msg([coinbase_tx(), funding], 1))

    assert first == (Match(1, Direction.INCOMING),)
    assert second == ()
    assert ingest.suppressed == 1


def test_a_transaction_seen_only_in_a_block_still_alerts(matcher):
    """The mempool message can simply be dropped — that is the whole reason this design
    distrusts the stream. The confirmation must not be suppressed by a de-duplication check
    for an alert that never happened."""
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)

    assert ingest.handle(block_msg([coinbase_tx(), funding], 1)) == (
        Match(1, Direction.INCOMING),
    )
    assert ingest.suppressed == 0


def test_a_replaced_spend_alerts_but_never_enters_the_record(matcher, index, k_match):
    """RBF, and transactions that simply never confirm. The alert is correct — someone is
    moving the coins — but nothing has to be un-written afterwards, because nothing was
    written. Under a first-sight record this is the case that requires a rollback path."""
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)
    ingest.handle(block_msg([coinbase_tx(), funding], 1))

    replaced = build_tx([(parse_tx(funding).txid, 0)], [OTHER])
    assert ingest.handle(tx_msg(replaced, 2)) == (Match(1, Direction.OUTGOING),)

    # It never confirms. The coin is still ours as far as the record is concerned, which is
    # also what the node's UTXO set will say when reconciliation asks.
    assert index.items_owning_outpoint(outpoint_hmac(k_match, parse_tx(funding).txid, 0)) == [1]


def test_a_spend_confirming_removes_the_coin(matcher, index):
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)
    ingest.handle(block_msg([coinbase_tx(), funding], 1))

    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])
    ingest.handle(block_msg([coinbase_tx(), spend], 2))

    assert index.outpoint_count == 0


def test_a_coin_arriving_and_leaving_inside_one_block_is_seen_doing_both(matcher, index):
    """Matching and applying alternate per transaction. Two passes — match everything, then
    apply everything — would miss the spend, because the coin it spends would not be in the
    record yet when its input was looked up."""
    funding = build_tx([(PREV, 0)], [COLD])
    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])

    ingest = StreamIngest(matcher)
    alerts = ingest.handle(block_msg([coinbase_tx(), funding, spend], 1))

    assert alerts == (Match(1, Direction.INCOMING), Match(1, Direction.OUTGOING))
    assert index.outpoint_count == 0


# ── the gap the rule creates, and the overlay that closes it ────────────────────────────────


def test_spending_an_unconfirmed_deposit_still_alarms(matcher, index):
    """The cost of the write rule, paid off.

    A deposit arrives and is spent again before it confirms. The record holds nothing for it —
    correctly, it is not confirmed — so without an in-memory overlay the spend would match
    nothing at all and no alarm would fire. A missed alarm is the failure this product exists
    to prevent, so the coin is armed in memory the moment the deposit is seen.
    """
    funding = build_tx([(PREV, 0)], [COLD])
    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])

    ingest = StreamIngest(matcher)
    ingest.handle(tx_msg(funding, 1))

    assert ingest.handle(tx_msg(spend, 2)) == (Match(1, Direction.OUTGOING),)
    assert index.outpoint_count == 0  # still nothing written


def test_the_overlay_is_handed_over_to_the_record_on_confirmation(matcher):
    """Two answers to one question is the bug this avoids: the memory-only copy is the one
    reconciliation is not allowed to see, so it must not outlive the record's copy."""
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = StreamIngest(matcher)
    ingest.handle(tx_msg(funding, 1))
    assert len(matcher.provisional) == 1

    ingest.handle(block_msg([coinbase_tx(), funding], 1))

    assert len(matcher.provisional) == 0
    # And the transaction that created them is released too. Freeing the coins while keeping
    # the bookkeeping is a leak the coin count cannot see — the bound would then start
    # evicting live coins to make room for transactions that confirmed long ago.
    assert matcher.provisional.pending_transactions == 0


def test_the_overlay_is_bounded(k_match, index):
    """A transaction dropped from the mempool never confirms, so it never arrives to be
    cleaned up. The bound is the only thing that eventually forgets it."""
    matcher = Matcher(k_match, index)
    matcher.provisional.maxlen = 2
    ingest = StreamIngest(matcher)

    for i in range(4):
        ingest.handle(tx_msg(build_tx([(PREV, i)], [COLD]), i + 1))

    assert len(matcher.provisional) == 2
    assert matcher.provisional.evicted == 2


# ── de-duplication ──────────────────────────────────────────────────────────────────────────


def test_the_seen_set_forgets_in_insertion_order():
    """Insertion order, not access order: what the bound protects against is age, not
    unpopularity, and a re-broadcast must not extend a transaction's stay."""
    seen = SeenTransactions(maxlen=2)
    assert seen.add(b"a") is True
    assert seen.add(b"b") is True
    assert seen.add(b"a") is False  # a re-broadcast keeps its original position
    seen.add(b"c")

    assert b"a" not in seen
    assert (b"b" in seen, b"c" in seen) == (True, True)
    assert seen.evicted == 1


def test_only_matching_transactions_are_remembered(matcher, contiguous_stream):
    """An alert is the only thing there is to suppress. Remembering every transaction on the
    network would make the bound a function of traffic rather than of alerts — and would be
    the one way this set could plausibly overflow."""
    ingest = StreamIngest(matcher)
    ingest.run(contiguous_stream)

    assert len(ingest.seen) == 0
    assert ingest.parsed == 120
