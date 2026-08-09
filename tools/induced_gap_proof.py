#!/usr/bin/env python3
"""Prove chain catch-up against a real node, by inducing a gap and requiring it repaired.

    export COLDWATCH_RPC_USER=aw
    read -rs -p "rpc password: " COLDWATCH_RPC_PASSWORD && export COLDWATCH_RPC_PASSWORD
    python tools/induced_gap_proof.py --blocks 6

The password is read from the environment, never from an argument — a command line is visible
in `ps` to every user on the box and lands in shell history. `read -rs` keeps it out of both.
See `BitcoinRpc.from_env` for the file-based sources, which are better still.

## What it proves, and why this shape

Issue #24 asks for an **induced** gap, repaired. A clean run proves the sockets connect, which
was never in doubt; what has never run against real data is the block path and the repair.

The gap is induced by starting the follower's tip a few blocks behind the chain and handing it
the current tip block. That is not a contrivance — it is exactly the state a service is in after
any downtime, and it is the state the fixtures model. The difference here is that every block is
real: real sizes, real script types, real segwit and taproot spends, thousands of transactions
the parser has never seen.

Then the part that matters. The script scans the window for a coin that was **created in one
block and spent in a later one**, and watches that script. If catch-up works, the record learns
about the deposit from the first block and the alarm fires from the second — an INCOMING and an
OUTGOING that no live stream delivered, reconstructed entirely from blocks the subscriber
"missed". A repair loop that has never caught anything is not known to work; this makes it catch
something.

## What it deliberately does not print

No addresses, no scriptPubKeys, no txids, no amounts — heights and counts only. The invariants
that forbid those in an alert (CONTRIBUTING §1, I1 and I2) are not suspended because the output
is going to a terminal; a terminal is where things get pasted from. The script watches a
stranger's script transiently, in memory, and stores nothing.

Read-only throughout: `getblockhash`, `getblock`, and nothing else. It cannot move funds, and it
asks the node for nothing outside the RPC whitelist.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from coldwatch.channels import Direction
from coldwatch.match import (
    InMemoryWatchIndex,
    Matcher,
    StreamIngest,
    StreamMessage,
    derive_subkeys,
    parse_block,
    spk_hmac,
)
from coldwatch.node.rpc import (
    BitcoinRpc,
    MissingCredentials,
    RpcError,
    RpcTransportError,
)
from coldwatch.reconcile import CatchUpFailed, ChainFollower, ChainTip

#: Not a credential and never used to protect anything: the matcher needs *a* key, and this
#: process holds no watch list worth keying. Generated fresh would be equally fine.
PROOF_KEY = b"induced-gap-proof-key-not-secret"


def fetch_block(rpc: BitcoinRpc, height: int):
    """One block at a height, raw, parsed by the same parser the socket path uses."""
    block_hash = rpc.call("getblockhash", height)
    raw = bytes.fromhex(rpc.call("getblock", block_hash, 0))
    return raw, parse_block(raw)


def find_spend_within(blocks: list) -> tuple[bytes, int, int] | None:
    """A scriptPubKey created in one block of the window and spent in a later one.

    Returns (spk, created_index, spent_index). Walks outputs forward, then looks for an input
    spending one of them — the same relationship the matcher looks for, computed independently
    so a bug in the matcher cannot make this agree with it by accident.
    """
    created: dict[tuple[bytes, int], tuple[bytes, int]] = {}
    for index, block in enumerate(blocks):
        for tx in block.transactions:
            for op in tx.inputs:
                found = created.get((op.txid, op.vout))
                if found is not None:
                    spk, created_index = found
                    if created_index < index:
                        return spk, created_index, index
            for out in tx.outputs:
                if out.spk:  # skip empty and OP_RETURN-only oddities
                    created[(tx.txid, out.vout)] = (out.spk, index)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--blocks",
        type=int,
        default=6,
        help="how many blocks to induce the gap over (default: 6)",
    )
    args = ap.parse_args()

    try:
        rpc = BitcoinRpc.from_env()
    except MissingCredentials as exc:
        print(f"credentials: {exc}", file=sys.stderr)
        return 2
    return run(rpc, args.blocks)


def run(rpc, blocks_back: int) -> int:
    """The proof itself, against any object with `.call`.

    Split from `main` so the whole thing can be driven by the test suite against a fake chain —
    CONTRIBUTING §2's rule is that anything can be exercised with no node, and a script that
    only ever runs in production is a script whose first run is also its first test.
    """

    class _Args:
        blocks = blocks_back

    args = _Args()

    try:
        tip_height = int(rpc.call("getblockcount"))
    except RpcError as exc:
        print(f"node refused getblockcount (rpc {exc.code})", file=sys.stderr)
        return 2
    except (RpcTransportError, ValueError, TypeError) as exc:
        # The type name only. An auth failure's detail can quote what was sent.
        print(f"could not reach the node: {type(exc).__name__}", file=sys.stderr)
        return 2

    start = tip_height - args.blocks
    print(f"tip is at {tip_height}; inducing a gap of {args.blocks} blocks from {start}\n")

    # ── survey the window, independently of anything under test ─────────────────────────────
    window = []
    for height in range(start, tip_height + 1):
        try:
            _, block = fetch_block(rpc, height)
        except RpcError as exc:
            # The likely cause is a window reaching below the prune height. Reported rather
            # than raised: a traceback at a production shell prompt, from someone who has just
            # typed a password, is the worst possible moment for one.
            print(
                f"\ncould not read block {height} (rpc {exc.code}) — if the node is pruned, "
                f"this window may reach below its prune height. Try a smaller --blocks.",
                file=sys.stderr,
            )
            return 2
        window.append(block)
    print(f"read {len(window)} blocks, {sum(len(b.transactions) for b in window)} transactions")

    found = find_spend_within(window)
    if found is None:
        print(
            f"\nno coin in this window was both created and spent inside it. Re-run with a "
            f"larger --blocks; {args.blocks} is a small sample of the chain.",
            file=sys.stderr,
        )
        return 1
    spk, created_index, spent_index = found
    print(
        f"found a coin created at height {start + created_index} and spent at "
        f"{start + spent_index} — watching it\n"
    )

    # ── set the follower behind, then hand it the tip ────────────────────────────────────────
    k_match = derive_subkeys(PROOF_KEY).match
    index = InMemoryWatchIndex([(1, spk_hmac(k_match, spk))])
    matcher = Matcher(k_match, index)

    behind = window[created_index - 1] if created_index > 0 else window[0]
    behind_height = start + max(created_index - 1, 0)
    follower = ChainFollower(
        rpc,
        tip=ChainTip(hash=behind.block_hash, height=behind_height),
        max_catch_up=args.blocks + 2,
    )
    ingest = StreamIngest(matcher, expand_block=follower.blocks_to_apply)

    try:
        tip_raw, _ = fetch_block(rpc, tip_height)
    except RpcError as exc:
        print(f"\ncould not read the tip block (rpc {exc.code})", file=sys.stderr)
        return 2
    print(f"follower starts at {behind_height}; delivering only the block at {tip_height}")

    try:
        alerts = ingest.handle(StreamMessage("rawblock", tip_raw, 1))
    except CatchUpFailed as exc:
        print(f"\nFAIL — catch-up did not close the gap: {exc}", file=sys.stderr)
        return 1

    # ── what must be true ────────────────────────────────────────────────────────────────────
    expected_fetched = tip_height - behind_height - 1
    directions = [a.direction for a in alerts]

    checks = [
        (
            f"refetched exactly the {expected_fetched} missed blocks",
            follower.fetched == expected_fetched,
            f"fetched {follower.fetched}",
        ),
        (
            "applied every block in the gap, plus the one delivered",
            ingest.blocks == expected_fetched + 1,
            f"applied {ingest.blocks}",
        ),
        ("no block failed to parse", ingest.malformed == 0, f"malformed {ingest.malformed}"),
        (
            "the deposit was seen (INCOMING)",
            Direction.INCOMING in directions,
            f"directions {[d.value for d in directions]}",
        ),
        (
            "the spend raised the alarm (OUTGOING)",
            Direction.OUTGOING in directions,
            f"directions {[d.value for d in directions]}",
        ),
        ("the coin left the record when spent", index.outpoint_count == 0, f"{index.outpoint_count} left"),
        (
            f"the follower ended at the tip ({tip_height})",
            follower.tip is not None and follower.tip.height == tip_height,
            f"ended at {follower.tip.height if follower.tip else None}",
        ),
        (
            "the record is not flagged as behind",
            ingest.tracker.needs_reconciliation is False,
            "still flagged",
        ),
    ]

    print()
    failed = 0
    for label, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  ({detail})"))
        failed += not ok

    print(
        f"\n{len(checks) - failed}/{len(checks)} checks passed · "
        f"{ingest.confirmed} transactions confirmed into the record · "
        f"{ingest.blocks} blocks applied"
    )
    if failed:
        print("\nThe gap was NOT repaired. Do not close #24 on this.", file=sys.stderr)
        return 1
    # Deliberately does not say "against the real node": this runs against whatever it was
    # handed, and the test suite hands it a fake. A script that claims more than it can check
    # is the same failure as a monitor that reports health it never measured.
    print("\nThe gap was induced and repaired.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
