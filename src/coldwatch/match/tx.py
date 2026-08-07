"""A minimal raw-transaction parser: enough to match, and deliberately no more.

The stream hands us ``rawtx`` bytes. All the matching loop needs from a transaction is *what
it spends* (input outpoints) and *what it pays* (output scriptPubKeys), plus the transaction's
own txid so a payment to a watched address can be added to the live UTXO set.

**Amounts are parsed and discarded.** Nothing downstream may carry a value: an alert does not
report one (invariant I2) and reconciliation compares outpoint sets, not balances. Skipping
the field rather than exposing it means no future caller can casually thread an amount into a
template — the same reasoning that keeps `Alert` frozen and thin.

Third-party dependencies would do this too. Sixty lines of stdlib beats a dependency in the
hot path of a service whose entire pitch is that it holds nothing worth stealing.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

__all__ = [
    "MalformedTransaction",
    "OutPoint",
    "Transaction",
    "TxOutput",
    "parse_tx",
]

#: A coinbase input references this outpoint, which does not exist. It must never be looked
#: up as a spend — one lookup per block, of a value no watch can own, but it would also mean
#: the loop believes something was spent when nothing was.
NULL_TXID = bytes(32)
COINBASE_VOUT = 0xFFFFFFFF


class MalformedTransaction(ValueError):
    """The bytes are not a transaction we can parse.

    Raised rather than returned because the caller's only sane response is to skip the
    message and carry on. ⚠️ The message never includes the offending bytes — they are public
    chain data so this is not an invariant, but a log line full of transaction hex is useless
    and crowds out the lines that matter.
    """


@dataclass(frozen=True)
class OutPoint:
    """What an input spends."""

    txid: bytes
    """32 bytes, **internal** order — see `keys.canonical_outpoint` for why that matters."""
    vout: int


@dataclass(frozen=True)
class TxOutput:
    """What an output pays to. No value field: see the module docstring."""

    vout: int
    spk: bytes


@dataclass(frozen=True)
class Transaction:
    txid: bytes
    """Internal byte order. For a segwit transaction this is the witness-stripped hash, so it
    is stable under witness malleability — the same identifier the UTXO set uses."""
    inputs: tuple[OutPoint, ...]
    """Empty for a coinbase: it spends nothing, so there is nothing to look up."""
    outputs: tuple[TxOutput, ...]
    is_coinbase: bool
    has_witness: bool


class _Reader:
    """Bounds-checked cursor. Every read can fail; none can silently return short."""

    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def take(self, n: int) -> bytes:
        end = self.pos + n
        if n < 0 or end > len(self.buf):
            raise MalformedTransaction("truncated transaction")
        out = self.buf[self.pos : end]
        self.pos = end
        return out

    def uint32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def varint(self) -> int:
        first = self.take(1)[0]
        if first < 0xFD:
            return first
        if first == 0xFD:
            return struct.unpack("<H", self.take(2))[0]
        if first == 0xFE:
            return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]

    def count(self, min_item_bytes: int) -> int:
        """A varint element count, sanity-checked against what is actually left.

        Guards against a corrupt length claiming four billion inputs: the reads would fail
        anyway, but failing immediately keeps a malformed message from costing a loop.
        """
        n = self.varint()
        if n * min_item_bytes > len(self.buf) - self.pos:
            raise MalformedTransaction("element count exceeds remaining bytes")
        return n


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_tx(raw: bytes) -> Transaction:
    """Parse a raw transaction, legacy or segwit.

    The fixtures are witness-free, but a live node publishes segwit transactions constantly,
    so the two paths are tested against each other rather than assumed equivalent.
    """
    r = _Reader(raw)
    r.uint32()  # version — parsed to advance, not used

    # BIP144: a segwit transaction inserts a 0x00 marker and a non-zero flag after the
    # version. The marker is unambiguous because a legacy transaction with zero inputs is
    # invalid, so a 0x00 in that position cannot be an input count.
    has_witness = False
    if len(raw) >= 6 and raw[4] == 0x00:
        if raw[5] == 0x00:
            raise MalformedTransaction("segwit marker with zero flag")
        r.take(2)
        has_witness = True

    n_in = r.count(41)  # 32 txid + 4 vout + 1 script length + 4 sequence
    if n_in == 0:
        raise MalformedTransaction("transaction has no inputs")
    inputs: list[OutPoint] = []
    for _ in range(n_in):
        txid = r.take(32)
        vout = r.uint32()
        r.take(r.count(1))  # scriptSig
        r.uint32()          # sequence
        inputs.append(OutPoint(txid=txid, vout=vout))

    is_coinbase = (
        len(inputs) == 1
        and inputs[0].txid == NULL_TXID
        and inputs[0].vout == COINBASE_VOUT
    )

    n_out = r.count(9)  # 8 value + 1 script length
    outputs: list[TxOutput] = []
    for vout in range(n_out):
        r.take(8)  # value — read past it deliberately; see the module docstring
        outputs.append(TxOutput(vout=vout, spk=r.take(r.count(1))))

    witness_start = r.pos
    if has_witness:
        for _ in range(n_in):
            for _ in range(r.count(1)):
                r.take(r.count(1))

    r.uint32()  # locktime
    if r.pos != len(raw):
        raise MalformedTransaction("trailing bytes after transaction")

    # The txid is the hash of the *witness-stripped* serialisation: version, the input and
    # output sections, locktime. Strip by slicing rather than re-serialising, which would
    # mean carrying every field — including the amounts this module refuses to expose.
    preimage = raw if not has_witness else raw[:4] + raw[6:witness_start] + raw[-4:]

    return Transaction(
        txid=_dsha256(preimage),
        inputs=() if is_coinbase else tuple(inputs),
        outputs=tuple(outputs),
        is_coinbase=is_coinbase,
        has_witness=has_witness,
    )
