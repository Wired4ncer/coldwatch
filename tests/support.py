"""Transaction builders for the tests.

Synthetic throughout: random-looking filler, never a real address or a real transaction
(CONTRIBUTING.md §4). Building transactions in the test rather than recording them is what
lets a test say "this exact output is watched" — which the recorded fixtures, deliberately
full of strangers' synthetic scripts, cannot.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = ["PREV", "build_block", "build_tx", "coinbase_tx", "dsha256", "spk", "varint"]

PREV = bytes(range(32))


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def spk(tag: int) -> bytes:
    """A witness-v0 keyhash script with a recognisable filler hash."""
    return b"\x00\x14" + bytes([tag]) * 20


def build_tx(
    inputs: list[tuple[bytes, int]],
    outputs: list[bytes],
    witness: list[list[bytes]] | None = None,
    script_sig: bytes = b"",
) -> bytes:
    """Serialise a transaction. With ``witness``, in segwit form; without, legacy form."""
    body = varint(len(inputs))
    for txid, vout in inputs:
        body += txid + struct.pack("<I", vout)
        body += varint(len(script_sig)) + script_sig
        body += struct.pack("<I", 0xFFFFFFFD)
    body += varint(len(outputs))
    for script in outputs:
        body += struct.pack("<Q", 100_000)
        body += varint(len(script)) + script

    raw = struct.pack("<I", 2)
    if witness is not None:
        raw += b"\x00\x01"
    raw += body
    if witness is not None:
        for items in witness:
            raw += varint(len(items))
            for item in items:
                raw += varint(len(item)) + item
    return raw + struct.pack("<I", 0)


def coinbase_tx(outputs: list[bytes] | None = None, height: int = 900_000) -> bytes:
    """A block's first transaction. Its input outpoint is null and must never be looked up."""
    return build_tx(
        [(bytes(32), 0xFFFFFFFF)],
        outputs if outputs is not None else [spk(0xCB)],
        script_sig=b"\x03" + height.to_bytes(3, "little"),
    )


def build_block(
    txs: list[bytes], prev: bytes = PREV, nonce: int = 0, count: int | None = None
) -> bytes:
    """Serialise a block: an 80-byte header, a transaction count, then the transactions.

    Built rather than recorded, for the same reason as `build_tx` — a recorded block could not
    say "this exact output is watched", and CONTRIBUTING.md §4 forbids real chain data anyway.
    The merkle root is filler: nothing in the ingest verifies it, and a test that pretended
    otherwise would be asserting something the code does not do.

    ``count`` overrides the declared transaction count, so a block can claim more than it
    carries — the shape a truncated block arrives in.
    """
    header = (
        struct.pack("<I", 0x20000000)   # version
        + prev                          # previous block hash, internal order
        + bytes(32)                     # merkle root — filler, never checked
        + struct.pack("<I", 1_770_000_000)  # time
        + struct.pack("<I", 0x17034701)     # bits
        + struct.pack("<I", nonce)
    )
    return header + varint(len(txs) if count is None else count) + b"".join(txs)
