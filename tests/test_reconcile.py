"""Catch-up: what happens when the block stream drops one.

The failure being repaired here is specific, and it is not the one the fixtures were built for.
Under the write rule, a dropped `rawtx` costs an alert's *latency* and nothing else — the block
that confirms it writes the record either way. A dropped `rawblock` costs correctness outright,
because blocks are the only writer: coins that arrived stay invisible and coins that left stay
armed, with the sequence counters perfectly contiguous throughout.

`FakeChain` below is a chain of blocks the follower can fetch from, so the repair can be driven
with no node and no network — and so the tests can hand it a *different* chain mid-flight, which
is how the reorg paths get exercised at all.
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
    parse_block,
    parse_tx,
    spk_hmac,
)
from coldwatch.node.rpc import RpcError, RpcTransportError
from coldwatch.reconcile import CatchUpFailed, ChainFollower, ChainTip, ReorgDetected
from support import PREV, build_block, build_tx, coinbase_tx, spk

COLD = spk(0xC0)
OTHER = spk(0x11)
GENESIS = bytes(32)


class FakeChain:
    """A chain of raw blocks, addressable the way bitcoind addresses them.

    Serves `getblockhash`, `getblock` and `getblockheader`, and nothing else — the follower is
    not allowed to need anything else, since every extra call is another thing to be unavailable
    on a pruned node at the moment repair is needed most.
    """

    def __init__(self, start_height: int = 900_000) -> None:
        self.start_height = start_height
        self.raw: list[bytes] = []
        self.pruned_below: int | None = None
        self.unreachable = False
        self.abandoned: set[bytes] = set()
        """Block hashes reorged out — `getblockheader` reports them with -1 confirmations."""
        self.calls: list[str] = []

    # ── building ────────────────────────────────────────────────────────────────────────────

    def add(self, txs: list[bytes]) -> bytes:
        """Append a block carrying these transactions; return its raw bytes."""
        prev = parse_block(self.raw[-1]).block_hash if self.raw else GENESIS
        raw = build_block([coinbase_tx(), *txs], prev=prev, nonce=len(self.raw))
        self.raw.append(raw)
        return raw

    def height_of(self, index: int) -> int:
        return self.start_height + index

    def block(self, index: int):
        return parse_block(self.raw[index])

    # ── the node's side ─────────────────────────────────────────────────────────────────────

    def call(self, method: str, *params: object, timeout: float | None = None) -> object:
        self.calls.append(method)
        if self.unreachable:
            raise RpcTransportError("node unreachable")

        if method == "getblockhash":
            index = int(params[0]) - self.start_height  # type: ignore[arg-type]
            if not 0 <= index < len(self.raw):
                raise RpcError(-8, "Block height out of range")
            return parse_block(self.raw[index]).block_hash[::-1].hex()

        if method == "getblock":
            block_hash = bytes.fromhex(str(params[0]))[::-1]
            verbosity = int(params[1]) if len(params) > 1 else 1
            if verbosity == 1:
                # The description. Modelled separately from the raw block because the whitelist
                # grants `getblock` and NOT `getblockheader` -- so this is the only way the
                # follower is allowed to learn a height, and a fake that answered
                # `getblockheader` too would hide that.
                if block_hash in self.abandoned:
                    return {"height": self.start_height, "confirmations": -1}
                index = self._index_of(block_hash)
                return {"height": self.height_of(index), "confirmations": len(self.raw) - index}
            index = self._index_of(block_hash)
            if self.pruned_below is not None and self.height_of(index) < self.pruned_below:
                raise RpcError(-1, "Block not available (pruned data)")
            return self.raw[index].hex()

        raise RpcError(-32601, f"Method not found: {method}")

    def _index_of(self, block_hash: bytes) -> int:
        for i, raw in enumerate(self.raw):
            if parse_block(raw).block_hash == block_hash:
                return i
        raise RpcError(-5, "Block not found")


@pytest.fixture
def index(k_match) -> InMemoryWatchIndex:
    return InMemoryWatchIndex([(1, spk_hmac(k_match, COLD))])


@pytest.fixture
def matcher(k_match, index) -> Matcher:
    return Matcher(k_match, index)


@pytest.fixture
def chain() -> FakeChain:
    return FakeChain()


def ingest_with(matcher: Matcher, follower: ChainFollower) -> StreamIngest:
    return StreamIngest(matcher, expand_block=follower.blocks_to_apply)


def block_msg(raw: bytes, seq: int) -> StreamMessage:
    return StreamMessage("rawblock", raw, seq)


# ── the ordinary path ───────────────────────────────────────────────────────────────────────


def test_a_contiguous_block_is_applied_without_asking_the_node_for_anything(matcher, chain):
    """Every RPC call during normal operation is a call that can fail during an outage — and
    this path runs every ten minutes forever. Once the follower knows where it is, the child of
    the block it applied is one above it *by definition*, so asking would be a round trip to be
    told what it already knows."""
    follower = ChainFollower(chain)
    ingest = ingest_with(matcher, follower)

    ingest.handle(block_msg(chain.add([build_tx([(PREV, 0)], [COLD])]), 1))
    calls_after_first = len(chain.calls)
    ingest.handle(block_msg(chain.add([]), 2))
    ingest.handle(block_msg(chain.add([]), 3))

    assert ingest.blocks == 3
    assert follower.fetched == 0
    assert len(chain.calls) == calls_after_first, "a contiguous block asked the node something"


def test_the_follower_never_calls_getblockheader(matcher, chain):
    """The node's RPC whitelist grants `getblock` and **not** `getblockheader`. The obvious
    implementation uses the latter, passes every test against a fake that answers anything, and
    fails against the real node — which is exactly how it was caught, by reading the whitelist
    rather than by running the suite.

    Asserted rather than remembered, because the natural call is the forbidden one.
    """
    follower = ChainFollower(chain)
    ingest = ingest_with(matcher, follower)
    ingest.handle(block_msg(chain.add([]), 1))

    chain.add([])
    delivered = chain.add([])
    ingest.handle(block_msg(delivered, 2))

    assert "getblockheader" not in chain.calls
    assert set(chain.calls) <= {"getblock", "getblockhash"}


def test_the_tip_advances_with_what_was_applied(matcher, chain):
    follower = ChainFollower(chain)
    ingest = ingest_with(matcher, follower)

    raw = chain.add([])
    ingest.handle(block_msg(raw, 1))

    assert follower.tip == ChainTip(hash=parse_block(raw).block_hash, height=chain.height_of(0))


def test_the_same_block_twice_is_applied_once(matcher, index, chain):
    """A re-publication, or a block we fetched ourselves that the socket then delivered.
    Applying it twice re-applies its spends against a record that has already moved on."""
    funding = build_tx([(PREV, 0)], [COLD])
    raw = chain.add([funding])
    ingest = ingest_with(matcher, ChainFollower(chain))

    ingest.handle(block_msg(raw, 1))
    ingest.handle(block_msg(raw, 2))

    assert ingest.blocks == 1
    assert index.outpoint_count == 1


# ── the repair ──────────────────────────────────────────────────────────────────────────────


def test_a_dropped_block_is_fetched_before_the_one_that_followed_it(matcher, index, chain):
    """The failure this module exists for. The block carrying the deposit is dropped by ZMQ —
    nothing is broken, the transport discarded it at the high-water mark — and the next block
    arrives as though nothing happened. Without repair the coin is never armed, and the spend
    that follows alarms nobody."""
    funding = build_tx([(PREV, 0)], [COLD])
    follower = ChainFollower(chain)
    ingest = ingest_with(matcher, follower)
    ingest.handle(block_msg(chain.add([]), 1))  # establishes where we are

    chain.add([funding])          # dropped in flight
    delivered = chain.add([])     # this one arrives
    alerts = ingest.handle(block_msg(delivered, 2))

    assert alerts == (Match(1, Direction.INCOMING),)
    assert index.outpoint_count == 1
    assert (follower.fetched, follower.catch_ups) == (1, 1)
    assert ingest.blocks == 3  # the primer, the one refetched, and the one that arrived


def test_the_spend_after_a_repaired_gap_alarms(matcher, chain):
    """End to end, and the point of the whole exercise: the alarm survives a lost block."""
    funding = build_tx([(PREV, 0)], [COLD])
    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(chain.add([]), 1))

    chain.add([funding])  # dropped
    spend = build_tx([(parse_tx(funding).txid, 0)], [OTHER])
    delivered = chain.add([spend])

    assert ingest.handle(block_msg(delivered, 2)) == (
        Match(1, Direction.INCOMING),
        Match(1, Direction.OUTGOING),
    )


def test_several_dropped_blocks_are_applied_oldest_first(matcher, index, chain):
    """Order is not cosmetic: the deposit is in the first dropped block and the spend is in the
    second, so applying them out of order loses the spend entirely — its input would be looked
    up against a record that has not learned about the coin yet."""
    funding = build_tx([(PREV, 0)], [COLD])
    follower = ChainFollower(chain)
    ingest = ingest_with(matcher, follower)
    ingest.handle(block_msg(chain.add([]), 1))

    chain.add([funding])
    chain.add([build_tx([(parse_tx(funding).txid, 0)], [OTHER])])
    delivered = chain.add([])
    alerts = ingest.handle(block_msg(delivered, 2))

    assert alerts == (Match(1, Direction.INCOMING), Match(1, Direction.OUTGOING))
    assert index.outpoint_count == 0
    assert follower.fetched == 2


def test_a_repaired_gap_clears_the_reconciliation_flag(matcher, chain):
    """And only once the blocks are actually applied. A flag cleared on the attempt turns a
    failing repair into a silent one."""
    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(chain.add([]), 1))
    chain.add([])
    delivered = chain.add([])
    ingest.tracker.flag_for_reconciliation()

    ingest.handle(block_msg(delivered, 2))

    assert ingest.tracker.needs_reconciliation is False


# ── when repair cannot work ─────────────────────────────────────────────────────────────────


def test_a_pruned_gap_fails_loudly_rather_than_skipping_the_block(matcher, chain):
    """The prune target *is* the catch-up window. Down longer than that and the blocks are
    simply gone — so the record cannot be made right, and the only honest thing left is to say
    so. Carrying on with a hole in the record is the failure invariant I5 forbids."""
    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(chain.add([]), 1))

    chain.add([build_tx([(PREV, 0)], [COLD])])
    delivered = chain.add([])
    chain.pruned_below = chain.height_of(2)  # the dropped block is below the prune height

    with pytest.raises(CatchUpFailed):
        ingest.handle(block_msg(delivered, 2))
    assert ingest.tracker.needs_reconciliation is True
    assert ingest.catch_up_failures == 1


def test_an_unreachable_node_leaves_the_flag_raised(matcher, chain):
    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(chain.add([]), 1))
    chain.add([])
    delivered = chain.add([])
    chain.unreachable = True

    with pytest.raises(CatchUpFailed):
        ingest.handle(block_msg(delivered, 2))
    assert ingest.tracker.needs_reconciliation is True


def test_a_reorged_tip_is_refused_rather_than_papered_over(matcher, chain):
    """The record holds no per-block provenance — the outpoint set records nothing about which
    block added which coin — so there is nothing to roll back and no way to repair this here.
    Saying so is the whole behaviour."""
    applied = chain.add([])
    chain.add([])
    chain.add([])
    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(applied, 1))

    chain.abandoned.add(parse_block(applied).block_hash)

    with pytest.raises(ReorgDetected):
        ingest.handle(block_msg(chain.raw[2], 2))


def test_a_block_at_or_below_the_tip_on_another_branch_is_a_reorg(matcher, chain):
    """A competing block at a height already applied. Not a gap — there is nothing between us
    and it to fetch — and treating it as one would subtract its way to a negative range and
    apply nothing at all, silently."""
    applied = chain.add([])
    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(applied, 1))

    competitor = build_block([coinbase_tx()], prev=GENESIS, nonce=99)
    chain.raw.append(competitor)  # so the header lookup resolves

    with pytest.raises(ReorgDetected):
        ingest.handle(block_msg(competitor, 2))


def test_a_gap_beyond_the_ceiling_is_refused_rather_than_ground_through(matcher, chain):
    """Thousands of getblock calls while the live stream backs up behind them makes an outage
    worse, not better. Past a point the answer is a re-baseline, not a catch-up."""
    for _ in range(6):
        chain.add([])
    ingest = ingest_with(matcher, ChainFollower(chain, max_catch_up=2))
    ingest.handle(block_msg(chain.raw[0], 1))

    with pytest.raises(CatchUpFailed):
        ingest.handle(block_msg(chain.raw[5], 2))


def test_blocks_fetched_during_a_reorg_are_chained_to_each_other(matcher, chain):
    """Heights alone are not evidence. If the chain moves while catch-up is walking it, the
    blocks at those heights can come from two different branches — and spliced together they
    produce a record that matches neither."""
    chain.add([])
    chain.add([])
    chain.add([])
    delivered = chain.add([])

    ingest = ingest_with(matcher, ChainFollower(chain))
    ingest.handle(block_msg(chain.raw[0], 1))

    # The *first* of the two blocks about to be fetched is replaced by one from another branch,
    # as a reorg during catch-up would do. Note where it does and does not show up: it still
    # descends from our tip, so the first check passes, and the block that arrived still
    # descends from the last block fetched, so that check passes too. The only evidence is that
    # the two fetched blocks do not chain to each other.
    chain.raw[1] = build_block([coinbase_tx()], prev=parse_block(chain.raw[0]).block_hash,
                               nonce=0xBEEF)

    with pytest.raises(ReorgDetected):
        ingest.handle(block_msg(delivered, 2))


# ── the first block a fresh service ever sees ───────────────────────────────────────────────


def test_a_fresh_follower_does_not_invent_a_starting_point(matcher, chain):
    """With no tip there is nothing to be behind. Guessing the node's current tip would silently
    skip everything that happened before the service started, which is exactly the hole the
    enrolment baseline scan exists to fill."""
    for _ in range(4):
        chain.add([])
    follower = ChainFollower(chain)
    ingest = ingest_with(matcher, follower)

    ingest.handle(block_msg(chain.raw[3], 1))

    assert follower.fetched == 0
    assert ingest.blocks == 1
