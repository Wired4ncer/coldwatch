"""Repair: making the record catch up with the chain after the stream failed us.

Which failure needs repairing changed when the write rule landed (docs/architecture.md §4), and
it is worth being precise about, because the obvious answer is now the wrong one.

**A dropped `rawtx` no longer costs correctness.** The record is written by blocks alone, so a
transaction lost at the high-water mark — all 832 of them in the measured 40-minute window —
arrives again in the block that confirms it, and the record ends up identical. What was lost is
the mempool alert: *latency*, not the record. That is a real cost, and it is not one repair can
recover, because the moment to have alerted has passed.

**A dropped `rawblock` costs correctness absolutely.** It is the only writer. Every confirmation
in that block is one the record never learns about: coins that arrived stay invisible, and coins
that left stay armed, so a later spend of one of them alarms about a coin that is already gone
while the real movement went unannounced. Nothing in the transaction stream repairs it, and the
sequence counters can be perfectly contiguous throughout.

So this module follows the chain rather than diffing the UTXO set. It notices that the block in
hand is not the child of the last one applied, and fetches what is missing by height before
letting it through. No plaintext, no descriptors, no scan.

⚠️ **The UTXO-set diff described in issue #4 is NOT here, and cannot be built against the
current schema.** `scantxoutset` takes descriptors, descriptors contain the scriptPubKey, and
the schema stores `spk_hmac` — one-way, by design. There is no way to reconstruct what to ask
the node about. Closing that gap is a schema and threat-model decision (an `spk_ct` under
`k_store`, or a whole-UTXO-set dump that needs no plaintext), not a coding one, and it is
recorded rather than quietly worked around. What this module does cover is the failure that was
actually measured; what it does not cover is stated in `ReorgDetected` and in the notes below.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from .match.block import Block, MalformedBlock, parse_block
from .node.rpc import BitcoinRpc, RpcError, RpcTransportError

__all__ = [
    "CatchUpFailed",
    "ChainFollower",
    "ChainTip",
    "ReorgDetected",
]

#: A ceiling on how many blocks one catch-up will fetch. Beyond this, something is wrong that
#: fetching will not fix — the service was down for days, or the tip we are chaining from is not
#: on this chain at all — and grinding through thousands of `getblock` calls while the live
#: stream backs up behind us makes it worse rather than better.
DEFAULT_MAX_CATCH_UP = 144  # roughly a day of blocks

#: `getblock` verbosity 0: the raw block, hex-encoded. The same bytes the SUB socket delivers,
#: which is what lets one parser serve both paths.
RAW_BLOCK = 0


class CatchUpFailed(Exception):
    """The gap could not be closed, so the record is knowingly behind the chain.

    Raised rather than logged. A caller that swallows this has a record that is wrong and a
    service that believes it is fine — which is the failure mode invariant I5 exists to forbid.
    """


class ReorgDetected(CatchUpFailed):
    """The last block we applied is no longer on the active chain.

    Not repairable here, and pretending otherwise would be worse than saying so. The record
    holds no per-block provenance — the UTXO table is a flat set of outpoint HMACs with nothing
    recording *which* block added each one — so there is nothing to roll back. A reorg can
    un-confirm a spend, which puts a coin back that we have already dropped, and re-confirm it
    in a different block, which we would then read as a fresh spend.

    Closing this properly needs the UTXO-set diff that the module docstring explains is blocked
    on the schema. Until then the honest behaviour is to stop and say so loudly.
    """


@dataclass(frozen=True)
class ChainTip:
    """The last block folded into the record.

    A single global pointer, deliberately not a per-item one. Invariant I3 forbids event history
    at rest because a timestamp beside a watched item intersects it with the public chain — but
    a chain tip says only *how far the service has read*, which is the same for every tenant and
    identifies none of them.
    """

    hash: bytes
    """Internal byte order, as `block.Block.block_hash` reports it."""
    height: int


class ChainFollower:
    """Hands blocks to the record in order, fetching any the stream did not deliver.

    Stateful and single-threaded by design: it is the thing that knows what has been applied, so
    two of them against one record would each believe the other's work was missing.
    """

    def __init__(
        self,
        rpc: BitcoinRpc,
        tip: ChainTip | None = None,
        *,
        max_catch_up: int = DEFAULT_MAX_CATCH_UP,
    ) -> None:
        self._rpc = rpc
        self.tip = tip
        """None until the first block is applied — a fresh service has no idea where it is, and
        guessing "the current tip" would silently skip whatever it missed before starting."""
        self.max_catch_up = max_catch_up
        self.fetched = 0
        """Blocks recovered by catch-up. The count of confirmations the stream lost."""
        self.catch_ups = 0

    def blocks_to_apply(self, block: Block) -> Iterator[Block]:
        """Yield every block the record still owes, in order, ending with ``block``.

        The caller applies each in turn and the tip advances behind it, so a failure part-way
        leaves the tip at the last block actually applied rather than at the one we hoped to
        reach. That is why this is a generator: the alternative, returning a list, invites a
        caller to apply them in a loop that cannot report where it stopped.
        """
        if self.tip is None:
            # Nothing to be behind, and nothing to count from — this is the only time the
            # height has to be asked for on the ordinary path.
            yield from self._advance(block, self._height_of(block))
            return

        if block.prev_hash == self.tip.hash:
            # The child of what we applied is one above it, by definition. Asking the node
            # would be a round trip per block to be told what we already know, on the path
            # that runs every ten minutes forever.
            yield from self._advance(block, self.tip.height + 1)
            return

        if self._already_applied(block):
            # A duplicate publication, or a block we fetched ourselves a moment ago and the
            # socket delivered afterwards. Applying it twice is not harmless: the spends would
            # be re-applied against a record that has already moved on.
            return

        self.catch_ups += 1
        target = self._height_of(block)
        for missing in self._fetch_gap(block, target):
            # The tip has advanced by the time each of these is evaluated, so the heights
            # count up from where we were rather than all landing on the same one.
            yield from self._advance(missing, self.tip.height + 1)
        yield from self._advance(block, target)

    def _advance(self, block: Block, height: int) -> Iterator[Block]:
        yield block
        self.tip = ChainTip(hash=block.block_hash, height=height)

    def _already_applied(self, block: Block) -> bool:
        assert self.tip is not None
        return block.block_hash == self.tip.hash

    def _fetch_gap(self, block: Block, target: int) -> list[Block]:
        """The blocks between our tip and ``block``, oldest first."""
        assert self.tip is not None

        if not self._on_active_chain(self.tip.hash):
            raise ReorgDetected("the last applied block is no longer on the active chain")

        missing = target - self.tip.height - 1
        if missing < 0:
            # The incoming block is at or below our tip but is not our tip: a competing branch.
            raise ReorgDetected("received a block at or below the tip on a different branch")
        if missing > self.max_catch_up:
            raise CatchUpFailed(f"{missing} blocks behind, beyond the catch-up ceiling")

        blocks = []
        expected_parent = self.tip.hash
        for height in range(self.tip.height + 1, target):
            fetched = self._fetch(height)
            if fetched.prev_hash != expected_parent:
                # Chain the fetched blocks to each other rather than trusting the heights.
                # A reorg *during* catch-up would otherwise splice two branches together and
                # produce a record that matches neither.
                raise ReorgDetected("fetched blocks do not form a chain")
            expected_parent = fetched.block_hash
            blocks.append(fetched)
            self.fetched += 1

        # Checked even when nothing was fetched. A block one above the tip whose parent is not
        # the tip is a competing branch, not a gap — `missing` is zero, so without this it
        # would sail through and be applied on top of a record it does not follow.
        parent = blocks[-1].block_hash if blocks else self.tip.hash
        if block.prev_hash != parent:
            raise ReorgDetected("the incoming block does not follow the chain we applied")
        return blocks

    def _fetch(self, height: int) -> Block:
        """One block by height, as raw bytes, parsed by the same parser the socket path uses.

        ⚠️ The node is pruned, so a block below the prune height is simply gone — the catch-up
        window *is* the prune target. Down longer than that and this fails rather than lying:
        losing precision about *when* something happened is survivable, inventing a record is
        not.
        """
        try:
            block_hash = self._rpc.call("getblockhash", height)
            raw = self._rpc.call("getblock", block_hash, RAW_BLOCK)
        except RpcError as exc:
            raise CatchUpFailed(f"node refused block {height} (rpc {exc.code})") from None
        except RpcTransportError:
            raise CatchUpFailed(f"node unreachable fetching block {height}") from None

        if not isinstance(raw, str):
            raise CatchUpFailed(f"block {height} did not come back as hex")
        try:
            return parse_block(bytes.fromhex(raw))
        except (MalformedBlock, ValueError):
            raise CatchUpFailed(f"block {height} did not parse") from None

    def _height_of(self, block: Block) -> int:
        """Ask the node how high a block sits. A block does not carry its own height.

        The coinbase carries one under BIP34, but reading it would mean trusting a field from
        the very stream that is under suspicion here, and the node knows the answer for certain.

        Only ever asked on the catch-up path and for the very first block, so the round trip is
        rare by construction — see `blocks_to_apply`, which counts heights locally while the
        blocks arrive in order.
        """
        try:
            return int(self._describe(block.block_hash)["height"])
        except (KeyError, TypeError, ValueError):
            raise CatchUpFailed("block description carried no usable height") from None

    def _on_active_chain(self, block_hash: bytes) -> bool:
        """Whether a block we already applied is still part of the best chain.

        The node reports negative confirmations for a block that has been reorged out, which is
        the only in-band way to learn that the ground moved under the record.
        """
        try:
            return int(self._describe(block_hash)["confirmations"]) >= 0
        except (KeyError, TypeError, ValueError):
            raise CatchUpFailed("block description carried no usable confirmation count") from None

    def _describe(self, block_hash: bytes) -> dict:
        """Height and confirmations for a block, via `getblock` at verbosity 1.

        ⚠️ **`getblockheader` is the natural call here and is deliberately not used.** The
        node's RPC whitelist for this service grants `getblock` and not `getblockheader`, so the
        obvious version of this fails against the real node while passing every test — a fake
        answers whatever it is asked. Verbosity 1 returns the same two fields plus a list of
        txids we ignore; that is a larger response, and it buys not having to widen a whitelist
        or restart a node that other things depend on.

        Keeping the whitelist narrow is worth more than the bytes: it is the difference between
        a compromised service being able to read the chain and being able to act on the node.
        """
        try:
            described = self._rpc.call("getblock", block_hash[::-1].hex(), 1)
        except RpcError as exc:
            raise CatchUpFailed(f"node refused a block description (rpc {exc.code})") from None
        except RpcTransportError:
            raise CatchUpFailed("node unreachable fetching a block description") from None
        if not isinstance(described, dict):
            raise CatchUpFailed("block description did not come back as an object")
        return described
