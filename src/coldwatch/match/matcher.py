"""The matching loop: HMAC-and-compare, and keeping the live outpoint set live.

Two lookups per transaction, in this order:

* every **input outpoint** against the UTXO set → **OUTGOING**, the alarm;
* every **output scriptPubKey** against the watch list → **INCOMING**, informational.

The two are independent: an input references some earlier transaction, an output is keyed by
*this* transaction's txid, and no transaction can spend an output it is itself creating. So
the drops and the adds touch disjoint outpoints and the loop order does not affect the UTXO
set. What the order *does* fix is which match is computed and reported first, and alarms go
first because they are the ones sent without jitter.

Everything here compares keyed hashes. Plaintext chain data is public, arrives from our own
node, is used within the call, and is never persisted.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from coldwatch.channels import Direction

from .keys import outpoint_hmac, spk_hmac
from .tx import Transaction

__all__ = ["InMemoryWatchIndex", "Match", "Matcher", "WatchIndex"]


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


class Matcher:
    """Compares one transaction against the index and reports what moved."""

    def __init__(self, k_match: bytes, index: WatchIndex) -> None:
        self._k = k_match
        self._index = index

    def process(self, tx: Transaction) -> tuple[Match, ...]:
        """Match one transaction, updating the live outpoint set as a side effect.

        Alarms come first in the returned tuple, so a caller that processes them in order
        sends the urgent one first. An item can legitimately appear twice — once outgoing,
        once incoming — when a spend pays change back to the same address; both are reported
        because *what to do about it* is an alerting-policy decision, not this loop's.
        """
        outgoing: list[int] = []
        incoming: list[int] = []

        for op in tx.inputs:  # empty for a coinbase: it spends nothing
            op_h = outpoint_hmac(self._k, op.txid, op.vout)
            for item_id in tuple(self._index.items_owning_outpoint(op_h)):
                if item_id not in outgoing:
                    outgoing.append(item_id)
                self._index.drop_outpoint(item_id, op_h)

        for out in tx.outputs:
            spk_h = spk_hmac(self._k, out.spk)
            items = self._index.items_watching_spk(spk_h)
            if not items:
                continue
            new_op = outpoint_hmac(self._k, tx.txid, out.vout)
            for item_id in items:
                if item_id not in incoming:
                    incoming.append(item_id)
                # Tracked regardless of the item's alert mode: `mute` suppresses the
                # notification, not the bookkeeping. A muted deposit that never entered the
                # UTXO set would be a spend we could not see later.
                self._index.add_outpoint(item_id, new_op)

        return tuple(
            [Match(i, Direction.OUTGOING) for i in outgoing]
            + [Match(i, Direction.INCOMING) for i in incoming]
        )
