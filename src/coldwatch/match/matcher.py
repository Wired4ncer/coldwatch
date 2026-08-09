"""The matching loop: HMAC-and-compare, and keeping the live outpoint set live.

Two lookups per transaction, in this order:

* every **input outpoint** against the UTXO set → **OUTGOING**, the alarm;
* every **output scriptPubKey** against the watch list → **INCOMING**, informational.

Alarms are computed and reported first because they are the ones sent without jitter.

**Matching and writing are separate calls, and that separation is the design.** `match` runs on
everything the stream carries; `apply` runs only on what a block confirms. A mempool
transaction therefore alerts — that is the product — without touching the record, because
`scantxoutset` reads confirmed state and a record written on first sight would make an
unconfirmed receipt indistinguishable from a missed spend. See docs/architecture.md §4; the
short version is that reconciliation can only repair a divergence it can interpret.

Everything here compares keyed hashes. Plaintext chain data is public, arrives from our own
node, is used within the call, and is never persisted.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from coldwatch.channels import Direction

from .keys import outpoint_hmac, spk_hmac
from .tx import Transaction

__all__ = [
    "InMemoryWatchIndex",
    "Match",
    "Matcher",
    "ProvisionalOutpoints",
    "WatchIndex",
]

#: Bound on mempool-only coins held in memory. Only coins paying a *watched* script are ever
#: held, so this is not sized against mempool traffic — reaching it would mean tens of thousands
#: of unconfirmed deposits to watched addresses at once.
DEFAULT_PROVISIONAL_MAX = 100_000


@dataclass(frozen=True)
class Match:
    """One watched item saw one kind of movement in one transaction.

    Carries no txid, no amount and no script: the alert layer has no use for them and
    invariant I2 says an alert may not report them, so they stop here rather than being
    threaded through and dropped later by discipline.
    """

    item_id: int
    direction: Direction


class WatchIndex(Protocol):
    """The lookups and mutations the loop needs, and nothing else.

    Narrow on purpose: in production this is SQLite (`watch_item` and `utxo`, see
    docs/architecture.md §3), and in tests it is a pair of dicts. The loop cannot tell.
    """

    def items_watching_spk(self, spk_hmac_: bytes) -> Sequence[int]:
        """Items watching this scriptPubKey. Several — two tenants may watch one address."""
        ...

    def items_owning_outpoint(self, outpoint_hmac_: bytes) -> Sequence[int]:
        ...

    def add_outpoint(self, item_id: int, outpoint_hmac_: bytes) -> None:
        ...

    def drop_outpoint(self, item_id: int, outpoint_hmac_: bytes) -> None:
        ...


class InMemoryWatchIndex:
    """A dict-backed index, for tests and for replaying a stream with no database.

    Not a production store: it holds no labels, no channels and no persistence. It exists so
    the matching logic can be exercised without SQLite, which is what makes the offline
    fixtures useful.
    """

    def __init__(self, watched: Iterable[tuple[int, bytes]] = ()) -> None:
        self._by_spk: dict[bytes, list[int]] = {}
        self._by_outpoint: dict[bytes, list[int]] = {}
        for item_id, spk_h in watched:
            self._by_spk.setdefault(spk_h, []).append(item_id)

    def items_watching_spk(self, spk_hmac_: bytes) -> Sequence[int]:
        return self._by_spk.get(spk_hmac_, ())

    def items_owning_outpoint(self, outpoint_hmac_: bytes) -> Sequence[int]:
        return self._by_outpoint.get(outpoint_hmac_, ())

    def add_outpoint(self, item_id: int, outpoint_hmac_: bytes) -> None:
        owners = self._by_outpoint.setdefault(outpoint_hmac_, [])
        if item_id not in owners:
            owners.append(item_id)

    def drop_outpoint(self, item_id: int, outpoint_hmac_: bytes) -> None:
        owners = self._by_outpoint.get(outpoint_hmac_)
        if not owners or item_id not in owners:
            return
        owners.remove(item_id)
        if not owners:
            del self._by_outpoint[outpoint_hmac_]

    @property
    def outpoint_count(self) -> int:
        return sum(len(v) for v in self._by_outpoint.values())


class ProvisionalOutpoints:
    """Coins that exist only in the mempool. **In memory, never in the record.**

    The confirmed-only write rule creates one gap, and this closes it: a deposit that arrives
    and is spent again before it confirms would otherwise never be armed, so the spend would
    match nothing and no alarm would fire. That is a missed alert — the failure the product
    exists to prevent — so the coin is tracked here, where reconciliation cannot see it and
    nothing is written to disk.

    It stays out of the record for the same reason the rule exists: `scantxoutset` will not
    report an unconfirmed coin, so a reconciliation pass that could see these would read every
    one of them as a coin the node has lost.

    Kept in RAM also because the alternative is worse than losing it on restart — a persisted
    "unconfirmed since" is a timestamp beside a chain event at rest, the correlation
    HMAC-at-rest exists to prevent (DESIGN §3b).
    """

    def __init__(self, maxlen: int = DEFAULT_PROVISIONAL_MAX) -> None:
        if maxlen < 1:
            raise ValueError("provisional bound must be at least 1")
        self.maxlen = maxlen
        self._by_outpoint: dict[bytes, list[int]] = {}
        self._by_txid: OrderedDict[bytes, list[bytes]] = OrderedDict()
        self.evicted = 0

    def add(self, txid: bytes, item_id: int, outpoint_hmac_: bytes) -> None:
        owners = self._by_outpoint.setdefault(outpoint_hmac_, [])
        if item_id not in owners:
            owners.append(item_id)
        created = self._by_txid.setdefault(txid, [])
        if outpoint_hmac_ not in created:
            created.append(outpoint_hmac_)
        while len(self._by_txid) > self.maxlen:
            _, stale_outpoints = self._by_txid.popitem(last=False)
            self._drop(stale_outpoints)
            self.evicted += 1

    def items(self, outpoint_hmac_: bytes) -> Sequence[int]:
        return self._by_outpoint.get(outpoint_hmac_, ())

    def forget(self, txid: bytes) -> None:
        """Drop a transaction's provisional coins — it confirmed, so the record now holds them.

        Also the only cleanup a never-confirming transaction gets, via the bound above: one
        that is dropped from the mempool never arrives in a block to trigger this.
        """
        self._drop(self._by_txid.pop(txid, ()))

    def _drop(self, outpoints: Iterable[bytes]) -> None:
        # Popped by outpoint, not filtered by owner: an outpoint hash commits to the txid that
        # created it, so no two transactions can produce the same one.
        for op_h in outpoints:
            self._by_outpoint.pop(op_h, None)

    def __len__(self) -> int:
        return len(self._by_outpoint)

    @property
    def pending_transactions(self) -> int:
        """Unconfirmed transactions still holding coins here.

        Tracked separately from the coin count because the two are released by different
        things, and a release that frees one without the other is a leak the coin count cannot
        see: the coins go, the transaction that created them stays, and the bound above starts
        evicting live coins to make room for dead bookkeeping.
        """
        return len(self._by_txid)


class Matcher:
    """Compares one transaction against the index and reports what moved."""

    def __init__(
        self,
        k_match: bytes,
        index: WatchIndex,
        provisional: ProvisionalOutpoints | None = None,
    ) -> None:
        self._k = k_match
        self._index = index
        self.provisional = provisional if provisional is not None else ProvisionalOutpoints()

    def match(self, tx: Transaction) -> tuple[Match, ...]:
        """What this transaction moves, changing nothing.

        Read-only because a mempool transaction must produce an alert without touching the
        record: `scantxoutset` reports confirmed state, so a record written on first sight
        makes an unconfirmed receipt indistinguishable from a missed spend, and reconciliation
        loses the ability to tell a repair from a false alarm (docs/architecture.md §4).

        Alarms come first in the returned tuple, so a caller that processes them in order
        sends the urgent one first. An item can legitimately appear twice — once outgoing,
        once incoming — when a spend pays change back to the same address; both are reported
        because *what to do about it* is an alerting-policy decision, not this loop's.
        """
        outgoing: list[int] = []
        incoming: list[int] = []

        for op in tx.inputs:  # empty for a coinbase: it spends nothing
            op_h = outpoint_hmac(self._k, op.txid, op.vout)
            # The record first, then the mempool-only coins. A spend of a deposit that has not
            # confirmed yet is still a spend, and it is the case the record cannot cover.
            for item_id in (
                *self._index.items_owning_outpoint(op_h),
                *self.provisional.items(op_h),
            ):
                if item_id not in outgoing:
                    outgoing.append(item_id)

        for out in tx.outputs:
            spk_h = spk_hmac(self._k, out.spk)
            for item_id in self._index.items_watching_spk(spk_h):
                if item_id not in incoming:
                    incoming.append(item_id)

        return tuple(
            [Match(i, Direction.OUTGOING) for i in outgoing]
            + [Match(i, Direction.INCOMING) for i in incoming]
        )

    def note_unconfirmed(self, tx: Transaction) -> None:
        """Arm the coins an **unconfirmed** transaction pays to watched scripts.

        Separate from `match` so the read stays a read, and separate from `apply` so that what
        lands in the record and what lands in memory can never be confused for one another.
        Called on the mempool path only.
        """
        for out in tx.outputs:
            spk_h = spk_hmac(self._k, out.spk)
            items = self._index.items_watching_spk(spk_h)
            if not items:
                continue
            op_h = outpoint_hmac(self._k, tx.txid, out.vout)
            for item_id in items:
                self.provisional.add(tx.txid, item_id, op_h)

    def apply(self, tx: Transaction) -> None:
        """Fold a **confirmed** transaction into the live outpoint set.

        Called from the block handler and from reconciliation repair, never from the mempool
        path. Drops what it spends, adds what it pays to a watched script.

        The two are independent — an input references some earlier transaction, an output is
        keyed by *this* transaction's txid, and no transaction can spend an output it is
        itself creating — so the drops and the adds touch disjoint outpoints and the order
        within one call cannot matter. Order *between* calls does: applying each transaction
        before matching the next is what lets a coin that arrives and leaves inside one block
        be seen doing both.
        """
        for op in tx.inputs:
            op_h = outpoint_hmac(self._k, op.txid, op.vout)
            for item_id in tuple(self._index.items_owning_outpoint(op_h)):
                self._index.drop_outpoint(item_id, op_h)

        for out in tx.outputs:
            spk_h = spk_hmac(self._k, out.spk)
            items = self._index.items_watching_spk(spk_h)
            if not items:
                continue
            new_op = outpoint_hmac(self._k, tx.txid, out.vout)
            for item_id in items:
                # Tracked regardless of the item's alert mode: `mute` suppresses the
                # notification, not the bookkeeping. A muted deposit that never entered the
                # UTXO set would be a spend we could not see later.
                self._index.add_outpoint(item_id, new_op)

        # The record now holds whatever this transaction created, so the in-memory copies are
        # redundant. Leaving them would mean two answers to one question, and the memory-only
        # one is the answer reconciliation is not allowed to see.
        self.provisional.forget(tx.txid)

    def process(self, tx: Transaction) -> tuple[Match, ...]:
        """Match a confirmed transaction and fold it in — the block path, in one call."""
        matches = self.match(tx)
        self.apply(tx)
        return matches
