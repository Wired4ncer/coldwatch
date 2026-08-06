#!/usr/bin/env python3
"""Replay a recorded transaction stream over ZMQ, as bitcoind would publish it.

Lets you build and test the matching loop with no Bitcoin node and no credentials.

    python tools/replay_zmq.py tests/fixtures/stream-sample.jsonl --port 28333
    python tools/replay_zmq.py tests/fixtures/with-gap.jsonl --port 28333

Fixture format is JSONL, one message per line:

    {"topic": "rawtx", "seq": 41, "hex": "0100...", "delay_ms": 120}

`seq` is the value published in the 3rd ZMQ message part — the counter bitcoind increments
per topic. A fixture may deliberately skip sequence numbers to simulate the high-water-mark
drops that a real node exhibits under load; see tests/fixtures/with-gap.jsonl.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path

try:
    import zmq
except ImportError:
    sys.exit("pyzmq is required:  pip install pyzmq")


def load(path: Path) -> list[dict]:
    msgs = []
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            msgs.append(json.loads(line))
        except json.JSONDecodeError as exc:
            sys.exit(f"{path}:{lineno}: {exc}")
    return msgs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fixture", type=Path)
    ap.add_argument("--port", type=int, default=28333)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--loop", action="store_true", help="repeat forever")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="time multiplier; 0 replays with no delays at all")
    ap.add_argument("--wait", type=float, default=30.0,
                    help="seconds to wait for a subscriber before replaying anyway")
    args = ap.parse_args()

    msgs = load(args.fixture)
    if not msgs:
        sys.exit(f"{args.fixture}: no messages")

    ctx = zmq.Context()
    sock = ctx.socket(zmq.PUB)
    monitor = sock.get_monitor_socket(zmq.EVENT_ACCEPTED)
    sock.bind(f"tcp://{args.bind}:{args.port}")

    # ZMQ's "slow joiner": a PUB socket silently discards anything published before a
    # subscriber has finished its handshake. A fixed sleep is not enough — replaying at
    # --speed 0 finishes in milliseconds and the subscriber sees nothing at all, which
    # looks like a broken fixture rather than a race. So wait for a real connection.
    print(f"bound tcp://{args.bind}:{args.port} — waiting for a subscriber "
          f"(timeout {args.wait}s, Ctrl-C to skip)", flush=True)
    deadline = time.time() + args.wait
    connected = False
    while time.time() < deadline:
        try:
            if monitor.poll(200):
                monitor.recv_multipart()
                connected = True
                break
        except KeyboardInterrupt:
            break
    if connected:
        # The handshake completes slightly after the accept event; without this the first
        # few messages are still lost.
        time.sleep(0.3)
        print("subscriber connected — replaying", flush=True)
    else:
        print("no subscriber connected; replaying anyway (messages will be discarded)",
              flush=True)

    sent = 0
    try:
        while True:
            for m in msgs:
                topic = m["topic"].encode()
                body = bytes.fromhex(m["hex"])
                seq = struct.pack("<I", int(m["seq"]))
                sock.send_multipart([topic, body, seq])
                sent += 1
                if args.speed > 0:
                    time.sleep(m.get("delay_ms", 50) / 1000.0 / args.speed)
            if not args.loop:
                break
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\nsent {sent} messages", flush=True)
        # The monitor socket must be closed before term(), or ctx.term() blocks forever
        # waiting on a socket the caller never sees. Silent hang on exit if forgotten.
        sock.disable_monitor()
        monitor.close()
        sock.close()
        ctx.term()


if __name__ == "__main__":
    main()
