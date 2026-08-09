"""Raw block parsing: the confirmation half of the ingest.

`rawblock` carries an 80-byte header followed by every transaction in the block, back to back
with no length prefix on any of them. That last detail is why `tx.read_tx` reports where it
stopped: the only way to find the second transaction is to have parsed the first exactly.

Under the write rule (docs/architecture.md §4) this topic is not a nice-to-have. It is the
**only** thing that mutates the stored UTXO set — the transaction stream alerts and nothing
more — so a block that goes unparsed is a set of confirmations the record never learns about.
That is survivable, because reconciliation exists to notice exactly this, but only if a failure
here *reaches* the reconciler instead of being counted and forgotten.

A block is ~1.7 MB, which is also why it gets its own SUB socket: sharing one with the
transaction stream is itself a cause of the drops the whole design is braced against.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .tx import MalformedTransaction, Transaction, read_tx

__all__ = ["HEADER_SIZE", "Block", "MalformedBlock", "parse_block"]

#: version 4 · prev hash 32 · merkle root 32 · time 4 · bits 4 · nonce 4
HEADER_SIZE = 80


class MalformedBlock(ValueError):
    """The bytes are not a block we can parse.

    ⚠️ Never swallow this. A skipped transaction costs one missed alert; a skipped block costs
    every confirmation in it, and under the confirmed-only write rule that is the record
    silently falling behind the chain. The handler's obligation is to flag for reconciliation,
    which is the only thing that can put it right.
    """


@dataclass(frozen=True)
class Block:
    """A parsed block: what it is, what came before it, and what it confirmed."""

    block_hash: bytes
    """32 bytes, **internal** order — the same orientation `keys.canonical_outpoint` wants.
    `keys.txid_to_display` reverses it for anything human-facing."""

    prev_hash: bytes
    """The parent. Reconciliation anchors its diff to a `bestblock`, and a chain of parents is
    what lets the handler tell "the tip moved on" from "the tip moved sideways" — a reorg."""

    transactions: tuple[Transaction, ...]


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_block(raw: bytes) -> Block:
    """Parse a raw block. Raises `MalformedBlock` rather than returning a partial one.

    Partial would be worse than useless here: half a block applied to the record is a state no
    chain ever had, and it would look exactly like a correctly applied one from the outside.
    """
    if len(raw) < HEADER_SIZE + 1:
        raise MalformedBlock("truncated block header")

    header = raw[:HEADER_SIZE]
    prev_hash = header[4:36]

    pos = HEADER_SIZE
    first = raw[pos]
    if first < 0xFD:
        count, pos = first, pos + 1
    elif first == 0xFD:
        count, pos = struct.unpack_from("<H", raw, pos + 1)[0], pos + 3
    elif first == 0xFE:
        count, pos = struct.unpack_from("<I", raw, pos + 1)[0], pos + 5
    else:
        count, pos = struct.unpack_from("<Q", raw, pos + 1)[0], pos + 9

    if count == 0:
        # Every block has a coinbase. Zero means we are not reading a block.
        raise MalformedBlock("block claims no transactions")
    # The smallest possible transaction is around 60 bytes; a corrupt count claiming millions
    # would fail on the reads anyway, but failing now costs a comparison instead of a loop.
    if count * 60 > len(raw) - pos:
        raise MalformedBlock("transaction count exceeds remaining bytes")

    transactions = []
    for _ in range(count):
        try:
            tx, pos = read_tx(raw, pos)
        except MalformedTransaction as exc:
            raise MalformedBlock(f"transaction {len(transactions)}: {exc}") from None
        transactions.append(tx)

    if pos != len(raw):
        # Trailing bytes mean the count was wrong or a transaction was misparsed, and either
        # way the transactions we just read are not trustworthy as a set.
        raise MalformedBlock("trailing bytes after the last transaction")

    return Block(
        block_hash=_dsha256(header),
        prev_hash=prev_hash,
        transactions=tuple(transactions),
    )
