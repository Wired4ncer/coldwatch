#!/usr/bin/env python3
"""Generate synthetic ZMQ stream fixtures.

Transactions are structurally valid and parseable but entirely synthetic — random keys, no
real addresses, nothing that ever existed on any chain. See CONTRIBUTING.md §4 for why no
real address goes in a fixture.

    python tools/make_fixtures.py

Writes tests/fixtures/stream-sample.jsonl and tests/fixtures/with-gap.jsonl.
"""
from __future__ import annotations

import json
import random
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def p2wpkh(rng: random.Random) -> bytes:
    """OP_0 <20-byte hash> — a witness-v0 keyhash output script."""
    return b"\x00\x14" + bytes(rng.getrandbits(8) for _ in range(20))


def make_tx(rng: random.Random, n_in: int = 1, n_out: int = 2) -> bytes:
    tx = struct.pack("<I", 2)                       # version
    tx += varint(n_in)
    for _ in range(n_in):
        tx += bytes(rng.getrandbits(8) for _ in range(32))   # prevout txid
        tx += struct.pack("<I", rng.randrange(0, 4))         # prevout vout
        tx += varint(0)                                      # empty scriptSig (segwit)
        tx += struct.pack("<I", 0xFFFFFFFD)                  # sequence
    tx += varint(n_out)
    for _ in range(n_out):
        tx += struct.pack("<Q", rng.randrange(1_000, 5_000_000))  # value, sats
        spk = p2wpkh(rng)
        tx += varint(len(spk)) + spk
    tx += struct.pack("<I", 0)                      # locktime
    return tx


def write(path: Path, msgs: list[dict], header: str) -> None:
    lines = [f"# {line}" for line in header.strip().splitlines()]
    lines += [json.dumps(m) for m in msgs]
    path.write_text("\n".join(lines) + "\n")
    print(f"{path.relative_to(path.parent.parent.parent)}: {len(msgs)} messages")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20260806)   # fixed seed: fixtures must be reproducible

    # ── contiguous stream, no drops ──────────────────────────────────────────
    msgs = []
    for seq in range(1, 121):
        msgs.append({
            "topic": "rawtx",
            "seq": seq,
            "hex": make_tx(rng).hex(),
            "delay_ms": rng.choice([20, 40, 70, 110]),
        })
    write(OUT / "stream-sample.jsonl", msgs,
          "Synthetic contiguous rawtx stream — no sequence gaps.\n"
          "Baseline: a correct gap detector must report ZERO gaps here.")

    # ── stream with drops, modelled on real high-water-mark loss ─────────────
    rng = random.Random(20260806)
    msgs, seq = [], 1
    # Gap sizes mirror what a real node actually dropped under load: a large burst,
    # a small one, and a medium one. Losses cluster around block arrival.
    drops = {40: 599, 75: 26, 100: 207}
    for i in range(1, 121):
        msgs.append({
            "topic": "rawtx",
            "seq": seq,
            "hex": make_tx(rng).hex(),
            "delay_ms": rng.choice([20, 40, 70, 110]),
        })
        seq += 1
        if i in drops:
            seq += drops[i]     # the dropped messages are simply never sent
    write(OUT / "with-gap.jsonl", msgs,
          "Synthetic rawtx stream with THREE deliberate sequence gaps: 599, 26 and 207\n"
          "messages missing. Gap sizes mirror real measured high-water-mark loss.\n"
          "A correct gap detector must report exactly 3 gaps totalling 832 messages.\n"
          "Nothing in the payload indicates a drop — the sequence counter is the only evidence.")


if __name__ == "__main__":
    main()
