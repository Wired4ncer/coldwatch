"""An in-process bitcoind stand-in, modelling the three behaviours that shape the supervisor.

`tools/fake_rpc.py` is the same idea over real HTTP, for driving the service by hand. This one
is for the test suite: no sockets, no ports, and a scan that "takes" whatever fraction of a
second the test asks for.

What it reproduces, because each one broke a design assumption:

1. **`start` blocks** until the scan finishes. `abort` therefore has to arrive on a different
   connection, from a different thread.
2. **Scans serialise.** A second `start` while one is running is rejected with `-8`.
3. **An abandoned client does not stop the scan.** If a call times out, the scan here keeps
   running exactly as the node's would — which is what makes an orphan possible to test.
"""

from __future__ import annotations

import threading
import time

from coldwatch.node.rpc import RpcError, RpcTransportError

__all__ = ["FakeRpc"]

TIP_HASH = "00" * 32


class FakeRpc:
    """Programmable node. Not thread-safe to configure; safe to call from several threads."""

    def __init__(
        self,
        *,
        scan_duration: float = 0.0,
        unspents: dict[bytes, list[tuple[bytes, int]]] | None = None,
        start_error: Exception | None = None,
        result_override: object | None = None,
    ) -> None:
        self.scan_duration = scan_duration
        #: scriptPubKey → [(txid in *internal* order, vout)]. The RPC hands back display order,
        #: so this class reverses on the way out; a test that gets this backwards would pass
        #: against a supervisor that also had it backwards.
        self.unspents = unspents or {}
        self.start_error = start_error
        self.result_override = result_override

        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.batch_sizes: list[int] = []
        self.aborts = 0

        self._lock = threading.Lock()
        self._running = False
        self._aborted = False
        self._started_at = 0.0
        self._concurrent_starts = 0

    @property
    def scan_running(self) -> bool:
        """True while a scan the client has walked away from is still burning a core."""
        with self._lock:
            return self._running

    @property
    def concurrent_start_attempts(self) -> int:
        return self._concurrent_starts

    def call(self, method: str, *params: object, timeout: float | None = None) -> object:
        self.calls.append((method, params))
        if method != "scantxoutset":
            raise RpcError(-32601, f"Method not found: {method}")

        action = params[0] if params else "status"
        if action == "abort":
            return self._abort()
        if action == "start":
            return self._start(list(params[1]) if len(params) > 1 else [], timeout)
        raise RpcError(-8, f"unsupported action {action!r}")

    def _abort(self) -> bool:
        with self._lock:
            self.aborts += 1
            if not self._running:
                return False
            self._aborted = True
            # Clears `_running` here rather than leaving it to the blocked `start` call to
            # notice. After a client has timed out there is no call left looping, and that is
            # exactly the orphan case — if abort could not clear it, nothing ever could.
            self._running = False
            return True

    def _start(self, descriptors: list[str], timeout: float | None) -> object:
        with self._lock:
            if self._running:
                self._concurrent_starts += 1
                raise RpcError(-8, 'Scan already in progress, use action "abort" or "status"')
            self._running = True
            self._aborted = False
            self._started_at = time.monotonic()
        self.batch_sizes.append(len(descriptors))

        if self.start_error is not None:
            with self._lock:
                self._running = False
            raise self.start_error

        deadline = self._started_at + self.scan_duration
        while True:
            with self._lock:
                if self._aborted:
                    self._running = False
                    raise RpcError(-1, "Scan aborted")
            now = time.monotonic()
            if now >= deadline:
                break
            if timeout is not None and now - self._started_at >= timeout:
                # The client gives up. The node does not: `_running` stays set, which is the
                # orphan. Only an explicit abort clears it.
                raise RpcTransportError("scantxoutset: TimeoutError")
            time.sleep(0.005)

        with self._lock:
            self._running = False

        if self.result_override is not None:
            return self.result_override

        unspents = []
        for descriptor in descriptors:
            spk = bytes.fromhex(descriptor[len("raw(") : -1])
            for txid, vout in self.unspents.get(spk, []):
                unspents.append(
                    {
                        "txid": txid[::-1].hex(),  # RPC reports display order
                        "vout": vout,
                        "scriptPubKey": spk.hex(),
                        "amount": 0.001,
                        "height": 900_000,
                    }
                )
        return {
            "success": True,
            "txouts": 165_813_573,
            "height": 961_336,
            "bestblock": TIP_HASH,
            "unspents": unspents,
            "total_amount": 0.001 * len(unspents),
        }
