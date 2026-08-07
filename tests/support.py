"""Transaction builders for the tests.

Synthetic throughout: random-looking filler, never a real address or a real transaction
(CONTRIBUTING.md §4). Building transactions in the test rather than recording them is what
lets a test say "this exact output is watched" — which the recorded fixtures, deliberately
full of strangers' synthetic scripts, cannot.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = ["PREV", "build_tx", "dsha256", "spk", "varint"]

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
