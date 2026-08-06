#!/usr/bin/env python3
"""A fake bitcoind JSON-RPC endpoint, with realistic scantxoutset behaviour.

Lets you develop the enrolment flow and the scan supervisor with no node access.

    python tools/fake_rpc.py --port 18332 --scan-delay 186

Implements only what the service actually calls: getblockcount, getbestblockhash,
getblockchaininfo, getrawmempool, uptime, scantxoutset (start/status/abort).

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
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TIP_HEIGHT = 961_336
TIP_HASH = "0000000000000000000055dac03a1a980589be6db0b21b0a29e8c91ef5b61664"

# RLock, not Lock: the scan handlers call _scan_done() while already holding the lock, and a
# plain Lock is not reentrant — that deadlocks the first scan and every request after it.
_scan_lock = threading.RLock()
_scan: dict | None = None       # {"started": float, "duration": float, "aborted": bool}


def _scan_progress() -> int | None:
    with _scan_lock:
        if _scan is None:
            return None
        pct = (time.time() - _scan["started"]) / _scan["duration"] * 100
        return min(99, int(pct))


def _scan_done() -> bool:
    with _scan_lock:
        return _scan is not None and (time.time() - _scan["started"]) >= _scan["duration"]


def handle(method: str, params: list, scan_delay: float) -> tuple[object, dict | None]:
    global _scan

    if method == "getblockcount":
        return TIP_HEIGHT, None
    if method == "getbestblockhash":
        return TIP_HASH, None
    if method == "uptime":
        return 1_800_000, None
    if method == "getblockchaininfo":
        return {
            "chain": "main", "blocks": TIP_HEIGHT, "headers": TIP_HEIGHT,
            "bestblockhash": TIP_HASH, "pruned": True, "pruneheight": 932_056,
            "initialblockdownload": False, "verificationprogress": 0.9999,
        }, None
    if method == "getrawmempool":
        return [], None

    if method == "scantxoutset":
        action = params[0] if params else "status"

        if action == "start":
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
            return {"success": True, "txouts": 165_813_573, "height": TIP_HEIGHT,
                    "bestblock": TIP_HASH, "unspents": [], "total_amount": 0}, None

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

        def do_POST(self) -> None:  # noqa: N802
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
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=18332)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--scan-delay", type=float, default=186.0,
                    help="seconds a scantxoutset takes (default: the real measured 186)")
    args = ap.parse_args()

    # Threading is required, not a nicety: a single-threaded server serialises requests at the
    # HTTP layer, so a second scantxoutset would politely wait its turn and then succeed —
    # hiding the very constraint this fixture exists to demonstrate.
    srv = ThreadingHTTPServer((args.bind, args.port), make_handler(args.scan_delay))
    print(f"fake bitcoind RPC on http://{args.bind}:{args.port}  "
          f"(scantxoutset takes {args.scan_delay}s)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)


if __name__ == "__main__":
    main()
