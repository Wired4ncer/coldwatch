"""The scan supervisor: one queue in front of a node that will only scan one thing at a time.

`scantxoutset` baselines a newly registered watch — it is how an item learns which coins it
already holds before the stream can tell it anything. Three measured properties of that call
shape everything here:

* **It takes ~186 seconds.** The scan walks the whole UTXO set, so it does not get faster for a
  better-chosen address. Enrolment cannot be synchronous.
* **Scans serialise.** bitcoind runs one at a time and rejects a concurrent start, so the
  supervisor has to be the only caller and everything else queues behind it.
* **An abandoned scan keeps running.** Dropping the client does not stop it. Only an explicit
  `abort` does, which makes every path out of this module — exception, shutdown, signal,
  process death — a path that owes the node an abort.

And one more, which is why batching exists at the bottom of this file: **the cost is the walk,
not the descriptor count.** Twenty-five descriptors in a single call cost roughly half again
what one costs, not twenty-five times. Scanning one item at a time would cap the service at
about nineteen enrolments an hour, which a launch would go straight through; batching makes
worst-case arming latency independent of how deep the queue is.

The half of issue #5 that is *not* here: `ARMING` as a user-visible state and the test-fire
ordering. Both need the enrolment API and a channel to fire into, neither of which exists yet.
This module is the mechanism they will sit on.
"""

from __future__ import annotations

import atexit
import contextlib
import queue
import signal
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Self

from .rpc import BitcoinRpc, RpcError, RpcTransportError

__all__ = [
    "ScanFailed",
    "ScanQueueFull",
    "ScanSupervisor",
    "ScanUtxo",
]

#: Measured: 25 descriptors in one call cost about half again what a single descriptor costs.
DEFAULT_BATCH_MAX = 25

#: How long to keep collecting after the first request before firing a batch. Pure latency
#: added to an enrolment that arrives alone; pure saving for one that arrives in a rush.
DEFAULT_BATCH_WINDOW = 5.0

#: Read timeout for the blocking `start` call. Generously above the measured ~186 s, because a
#: timeout here does not cancel anything — it abandons a scan that keeps running. Short
#: timeouts *cause* orphans.
DEFAULT_SCAN_TIMEOUT = 900.0

#: Abort and status are quick, and must not inherit the scan's patience.
CONTROL_TIMEOUT = 30.0

DEFAULT_QUEUE_MAXSIZE = 100

#: How long the worker sits on an empty queue before looking up. Only a ceiling: a queued
#: request wakes `get` immediately, and shutdown wakes it with a sentinel rather than
#: waiting this out — a service that takes a fifth of a second longer to die than it needs
#: to is trivial, but it is also trivial to not do.
IDLE_POLL = 0.2


class ScanQueueFull(Exception):
    """The queue is at its bound. Enrolment must refuse rather than promise.

    A queue with no bound is a promise the service cannot keep: at ~186 s a scan, a thousand
    queued items is a two-day wait that nobody is told about. Refusing is the honest answer,
    and it is the one invariant I5 asks for.
    """


class ScanFailed(Exception):
    """A scan did not produce a baseline for this request.

    Carries a code and nothing else. The node's own message may quote the descriptor it
    rejected, and a descriptor contains a watched scriptPubKey — so it stops at the boundary
    rather than travelling into a caller's log (invariant I1, and its usual trap: exception
    handlers).
    """

    def __init__(self, detail: str, code: int | None = None) -> None:
        super().__init__(detail if code is None else f"{detail} (rpc {code})")
        self.code = code


@dataclass(frozen=True)
class ScanUtxo:
    """One unspent output the node reported for a watched script.

    Plain chain data, deliberately not HMAC'd here: this module never sees a key. The caller
    hashes these under `k_match` and stores the result. Also deliberately not `match.tx`'s
    `OutPoint` — importing it would tie the package that talks to bitcoind to the package that
    does the matching, and reconciliation is about to need both.
    """

    txid: bytes
    """32 bytes, internal order — the same orientation `match.keys.canonical_outpoint` wants."""
    vout: int
    spk: bytes


@dataclass
class _Request:
    spk: bytes
    future: Future


class ScanSupervisor:
    """Serialises, batches and supervises `scantxoutset` calls against one node."""

    def __init__(
        self,
        rpc: BitcoinRpc,
        *,
        batch_max: int = DEFAULT_BATCH_MAX,
        batch_window: float = DEFAULT_BATCH_WINDOW,
        scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
    ) -> None:
        self._rpc = rpc
        self.batch_max = batch_max
        self.batch_window = batch_window
        self.scan_timeout = scan_timeout
        self._queue: queue.Queue[_Request | None] = queue.Queue(maxsize=queue_maxsize)
        self._stopping = threading.Event()
        self._scan_in_flight = threading.Event()
        self._worker: threading.Thread | None = None
        self._closed = False
        self.orphans_aborted = 0
        """Scans found already running at startup — someone died without aborting."""
        self.batches_run = 0

    # ── lifecycle ───────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Abort anything the last process left behind, then begin serving the queue.

        The startup abort is not belt-and-braces. `SIGKILL`, a power cut and an OOM kill cannot
        be intercepted, so no amount of care on the way out covers them — the only complete
        answer to "did we leave a scan running?" is to ask on the way *in*.
        """
        if self._worker is not None:
            raise RuntimeError("supervisor already started")
        if self._abort_scan():
            self.orphans_aborted += 1
        self._worker = threading.Thread(target=self._run, name="scan-supervisor", daemon=True)
        self._worker.start()
        atexit.register(self.close)

    def install_signal_handlers(self) -> None:
        """Abort on SIGTERM and SIGINT. Call this from the service entrypoint.

        Opt-in because installing process-wide handlers is not a library's decision to make
        silently. It matters, though: `atexit` does **not** run on SIGTERM, and SIGTERM is what
        a container stop sends — so without this the ordinary shutdown path is also an
        orphan-leaving path.
        """
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous = signal.getsignal(sig)

            def handler(signum, frame, _previous=previous):
                self.close()
                if callable(_previous):
                    _previous(signum, frame)

            signal.signal(sig, handler)

    def close(self, timeout: float = 30.0) -> None:
        """Stop serving, abort any scan in flight, fail anything still queued.

        Idempotent: `atexit` and an explicit call will both fire, and a shutdown path that
        raises on its second visit is a shutdown path that leaves a scan running.
        """
        if self._closed:
            return
        self._closed = True
        self._stopping.set()
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)  # wake the worker now rather than at its next poll
        if self._scan_in_flight.is_set():
            # From this thread, over its own connection — the worker is blocked inside `start`.
            self._abort_scan()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
            self._worker = None
        self._drain_queue(ScanFailed("supervisor shut down"))

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ── submission ──────────────────────────────────────────────────────────────────────────

    def submit(self, spk: bytes) -> Future:
        """Queue a baseline scan for one scriptPubKey.

        Returns a `Future` resolving to `tuple[ScanUtxo, ...]`. It stays pending for as long as
        the scan takes, which is the point: the caller marks the item ARMING and tells the user.
        """
        if self._closed:
            raise ScanFailed("supervisor is closed")
        request = _Request(spk=spk, future=Future())
        try:
            self._queue.put_nowait(request)
        except queue.Full:
            raise ScanQueueFull("scan queue is full") from None
        return request.future

    def pending(self) -> int:
        """Requests waiting for a batch. What a queued user's position is derived from."""
        return self._queue.qsize()

    # ── the worker ──────────────────────────────────────────────────────────────────────────

    def _run(self) -> None:
        while not self._stopping.is_set():
            batch = self._collect()
            if self._stopping.is_set():
                # Collected just as shutdown began. Starting a ~186 s scan on the way out would
                # be worse than useless: it is the orphan, created deliberately.
                self._fail(batch, ScanFailed("supervisor shut down"))
                return
            if batch:
                self._execute(batch)

    def _collect(self) -> list[_Request]:
        """Take one request, then as many more as arrive within the batch window.

        Whatever is already queued is taken immediately — a backlog does not need waiting for.
        The window only applies once the queue runs dry, so a lone enrolment pays it and a rush
        does not.
        """
        try:
            first = self._queue.get(timeout=IDLE_POLL)
        except queue.Empty:
            return []
        if first is None:
            return []
        batch = [first]

        while len(batch) < self.batch_max:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                return batch
            batch.append(item)

        deadline = time.monotonic() + self.batch_window
        while len(batch) < self.batch_max and not self._stopping.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                item = self._queue.get(timeout=remaining)
            except queue.Empty:
                break
            if item is None:
                return batch
            batch.append(item)
        return batch

    def _execute(self, batch: list[_Request]) -> None:
        live = [r for r in batch if r.future.set_running_or_notify_cancel()]
        if not live:
            return

        # One descriptor per distinct script: two tenants may watch the same address, and
        # asking the node about it twice would cost real seconds for an identical answer.
        by_spk: dict[bytes, list[_Request]] = {}
        for request in live:
            by_spk.setdefault(request.spk, []).append(request)

        # `raw(<hex>)` takes the script itself, so no address encoding is involved and no
        # address string is ever built to be sent anywhere.
        descriptors = [f"raw({spk.hex()})" for spk in by_spk]

        self._scan_in_flight.set()
        try:
            result = self._rpc.call(
                "scantxoutset", "start", descriptors, timeout=self.scan_timeout
            )
        except RpcError as exc:
            self._fail(live, ScanFailed("node rejected the scan", exc.code))
            return
        except RpcTransportError:
            self._fail(live, ScanFailed("node unreachable during scan"))
            return
        finally:
            self._scan_in_flight.clear()
            self.batches_run += 1

        if not isinstance(result, dict) or not result.get("success"):
            self._fail(live, ScanFailed("scan did not complete"))
            return

        found: dict[bytes, list[ScanUtxo]] = {spk: [] for spk in by_spk}
        for entry in result.get("unspents", []):
            try:
                spk = bytes.fromhex(entry["scriptPubKey"])
                utxo = ScanUtxo(
                    txid=bytes.fromhex(entry["txid"])[::-1],  # RPC gives display order
                    vout=int(entry["vout"]),
                    spk=spk,
                )
            except (KeyError, ValueError, TypeError):
                self._fail(live, ScanFailed("scan result was malformed"))
                return
            if spk in found:
                found[spk].append(utxo)
            # An unspent for a script nobody asked about would mean the node answered a
            # different question than the one we asked. Dropping it is the safe reading:
            # a baseline that includes a stranger's coin is worse than one that is short.

        for spk, requests in by_spk.items():
            outcome = tuple(found[spk])
            for request in requests:
                request.future.set_result(outcome)

    # ── node control ────────────────────────────────────────────────────────────────────────

    def _abort_scan(self) -> bool:
        """Ask the node to stop scanning. True if there was something to stop.

        Errors are swallowed on purpose: this runs on shutdown and startup paths where raising
        would replace a recoverable orphan with an unrecoverable one.
        """
        try:
            return bool(self._rpc.call("scantxoutset", "abort", timeout=CONTROL_TIMEOUT))
        except (RpcError, RpcTransportError):
            return False

    def _fail(self, requests: list[_Request], error: ScanFailed) -> None:
        for request in requests:
            if not request.future.done():
                request.future.set_exception(error)

    def _drain_queue(self, error: ScanFailed) -> None:
        while True:
            try:
                request = self._queue.get_nowait()
            except queue.Empty:
                return
            if request is not None and not request.future.done():
                request.future.set_exception(error)
