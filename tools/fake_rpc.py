#!/usr/bin/env python3
"""A fake bitcoind JSON-RPC endpoint, with realistic scantxoutset behaviour.

Lets you develop the enrolment flow and the scan supervisor with no node access.

    python tools/fake_rpc.py --port 18332 --scan-delay 186
    python tools/fake_rpc.py --port 18332 --scan-delay 2 --utxos my-coins.json

Implements only what the service actually calls: getblockcount, getbestblockhash,
getblockchaininfo, getrawmempool, uptime, scantxoutset (start/status/abort) — plus the
`_fake_*` control methods described below, which no real node has.

Why the default delay is 186 seconds
------------------------------------
That is the measured duration of a real `scantxoutset` against the production node. The scan
walks the whole UTXO set (~166M outputs), so it does not get faster for a better-chosen
address, and it grows over time. Three behaviours here are modelled from the real thing and
exist so you can test against them rather than discover them in production:

  1. It is slow enough that enrolment cannot be synchronous.
  2. Scans SERIALISE — a second `start` while one is running returns an error, as bitcoind does.
  3. An abandoned scan KEEPS RUNNING. Dropping the client does not stop it; only an explicit
     `abort` does. A supervisor that dies without aborting leaves a scan burning a core.

Use --scan-delay 2 for fast iteration, but run the real number before believing the flow works.

Why it holds a UTXO set
-----------------------
Reconciliation asks one question: *does the node still hold the coins we think it holds?* A
fixture whose `scantxoutset` always answered `"unspents": []` could not express the node
holding anything, so every reconciliation run against it looked like total loss and the repair
path could not be driven at all. It now holds a set, seeded from `--utxos` and mutable at
runtime:

    _fake_receive [{"spk": <hex>, "txid": <hex, display order>, "vout": <int>}, ...]
    _fake_spend   [{"txid": <hex, display order>, "vout": <int>}, ...]
    _fake_advance [<blocks>]        # move the tip on, with it a new bestblock hash
    _fake_utxos                     # dump the current set

⚠️ The `_fake_` prefix is load-bearing. These are not bitcoind methods, and service code must
never call one — the prefix means such a call fails loudly against a real node with
`Method not found` rather than quietly working in every environment that matters less.

⚠️ **Confirmed only.** The set here models the chainstate, which is what `scantxoutset` reads.
There is no mempool in it, deliberately: the rule the service is built on is that the stream
alerts and only confirmations write the record, so a fixture that let you "receive" into the
mempool would model a state the reconciler is defined never to see.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TIP_HEIGHT = 961_336

# RLock, not Lock: the scan handlers call _scan_done() while already holding the lock, and a
# plain Lock is not reentrant — that deadlocks the first scan and every request after it.
_scan_lock = threading.RLock()
_scan: dict | None = None       # {"started": float, "duration": float, "aborted": bool}

# The chainstate. scriptPubKey hex → {(txid hex in *display* order, vout)}. Display order
# because that is what the RPC speaks on both the way in and the way out; the service reverses
# it at its own boundary, and doing it here too would cancel the bug rather than expose it.
_chain_lock = threading.Lock()
_utxos: dict[str, set[tuple[str, int]]] = {}
_height = TIP_HEIGHT


def _tip_hash(height: int) -> str:
    """A deterministic stand-in for a block hash, with a plausible number of leading zeros.

    Derived from the height so that advancing the tip changes it — reconciliation anchors its
    diff to a `bestblock`, so a fixture whose hash never moved could not exercise the skew.
    """
    digest = hashlib.sha256(str(height).encode()).hexdigest()
    return "0" * 12 + digest[12:]


def _load_utxos(path: Path) -> dict[str, set[tuple[str, int]]]:
    """Read a seed set: a JSON list of {"spk", "txid", "vout"}, all hex in display order."""
    loaded: dict[str, set[tuple[str, int]]] = {}
    for entry in json.loads(path.read_text()):
        loaded.setdefault(entry["spk"], set()).add((entry["txid"], int(entry["vout"])))
    return loaded


def _scan_progress() -> int | None:
    with _scan_lock:
        if _scan is None:
            return None
        pct = (time.time() - _scan["started"]) / _scan["duration"] * 100
        return min(99, int(pct))


def _scan_done() -> bool:
    with _scan_lock:
        return _scan is not None and (time.time() - _scan["started"]) >= _scan["duration"]


def _snapshot(descriptors: list[str]) -> tuple[list[dict], int, str]:
    """The unspents matching these descriptors, and the tip they were read at.

    Read under one lock so the height and the coins agree with each other. A snapshot whose
    coins came from after its own `bestblock` would hand the reconciler a divergence that never
    existed on any chain.
    """
    unspents = []
    with _chain_lock:
        for descriptor in descriptors:
            if not (descriptor.startswith("raw(") and descriptor.endswith(")")):
                continue  # only raw() is implemented: it is the only form the service builds
            spk = descriptor[len("raw(") : -1]
            for txid, vout in sorted(_utxos.get(spk, ())):
                unspents.append({
                    "txid": txid, "vout": vout, "scriptPubKey": spk,
                    "desc": descriptor, "amount": 0.001, "height": 900_000,
                })
        return unspents, _height, _tip_hash(_height)


def handle(method: str, params: list, scan_delay: float) -> tuple[object, dict | None]:
    global _scan, _height

    if method == "getblockcount":
        with _chain_lock:
            return _height, None
    if method == "getbestblockhash":
        with _chain_lock:
            return _tip_hash(_height), None
    if method == "uptime":
        return 1_800_000, None
    if method == "getblockchaininfo":
        with _chain_lock:
            height, tip = _height, _tip_hash(_height)
        return {
            "chain": "main", "blocks": height, "headers": height,
            "bestblockhash": tip, "pruned": True, "pruneheight": 932_056,
            "initialblockdownload": False, "verificationprogress": 0.9999,
        }, None
    if method == "getrawmempool":
        return [], None

    if method == "_fake_receive":
        with _chain_lock:
            for entry in params[0] if params else []:
                _utxos.setdefault(entry["spk"], set()).add((entry["txid"], int(entry["vout"])))
        return True, None

    if method == "_fake_spend":
        spent = 0
        with _chain_lock:
            for entry in params[0] if params else []:
                key = (entry["txid"], int(entry["vout"]))
                for spk, coins in list(_utxos.items()):
                    if key in coins:
                        coins.discard(key)
                        spent += 1
                        if not coins:
                            del _utxos[spk]
        return spent, None

    if method == "_fake_advance":
        with _chain_lock:
            _height += int(params[0]) if params else 1
            return {"blocks": _height, "bestblockhash": _tip_hash(_height)}, None

    if method == "_fake_utxos":
        with _chain_lock:
            return [
                {"spk": spk, "txid": txid, "vout": vout}
                for spk, coins in sorted(_utxos.items())
                for txid, vout in sorted(coins)
            ], None

    if method == "scantxoutset":
        action = params[0] if params else "status"

        if action == "start":
            descriptors = list(params[1]) if len(params) > 1 else []
            with _scan_lock:
                if _scan is not None and not _scan_done():
                    # bitcoind refuses concurrent scans. Enrolment must queue.
                    return None, {"code": -8, "message": "Scan already in progress, use action \"abort\" or \"status\""}
                _scan = {"started": time.time(), "duration": scan_delay, "aborted": False}
            # Block until done, exactly as the real call does.
            while not _scan_done():
                with _scan_lock:
                    if _scan is None or _scan["aborted"]:
                        return None, {"code": -1, "message": "Scan aborted"}
                time.sleep(0.2)
            with _scan_lock:
                _scan = None
            # Read the set *after* the wait, not before: a real scan reports the chainstate it
            # finished on, and 186 seconds is long enough for that to matter.
            unspents, height, tip = _snapshot(descriptors)
            return {"success": True, "txouts": 165_813_573, "height": height,
                    "bestblock": tip, "unspents": unspents,
                    "total_amount": round(0.001 * len(unspents), 8)}, None

        if action == "status":
            pct = _scan_progress()
            return ({"progress": pct} if pct is not None else None), None

        if action == "abort":
            with _scan_lock:
                if _scan is None:
                    return False, None
                _scan["aborted"] = True
                _scan = None
            return True, None

    return None, {"code": -32601, "message": f"Method not found: {method}"}


def make_handler(scan_delay: float):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self.send_error(400, "bad JSON")
                return

            result, error = handle(req.get("method", ""), req.get("params", []), scan_delay)
            payload = json.dumps({"result": result, "error": error,
                                  "id": req.get("id")}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *a) -> None:
            print(f"  rpc: {fmt % a}", flush=True)

    return Handler


def main() -> None:
    global _utxos

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=18332)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--scan-delay", type=float, default=186.0,
                    help="seconds a scantxoutset takes (default: the real measured 186)")
    ap.add_argument("--utxos", type=Path,
                    help="JSON list of {spk, txid, vout} to seed the chainstate with")
    args = ap.parse_args()

    if args.utxos:
        _utxos = _load_utxos(args.utxos)

    # Threading is required, not a nicety: a single-threaded server serialises requests at the
    # HTTP layer, so a second scantxoutset would politely wait its turn and then succeed —
    # hiding the very constraint this fixture exists to demonstrate.
    srv = ThreadingHTTPServer((args.bind, args.port), make_handler(args.scan_delay))
    coins = sum(len(v) for v in _utxos.values())
    print(f"fake bitcoind RPC on http://{args.bind}:{args.port}  "
          f"(scantxoutset takes {args.scan_delay}s, chainstate holds {coins} coins)", flush=True)
    if not coins:
        print("  note: no coins seeded — every scan will report an empty set. Use --utxos, or "
              "_fake_receive, before concluding anything about reconciliation.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)


if __name__ == "__main__":
    main()
