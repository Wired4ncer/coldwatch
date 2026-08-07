"""The scan supervisor: queueing, batching, and the several ways to leave a scan running.

The orphan tests are the ones that matter. A scan nobody aborted burns a core on the node
indefinitely, and it is invisible from this side — the client that started it has already
walked away. Every path out of the supervisor is checked for it, including the two that cannot
be intercepted at all and are therefore handled on the way *in*.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import threading
import time

import pytest

from coldwatch.node import ScanFailed, ScanQueueFull, ScanSupervisor
from coldwatch.node.rpc import RpcError, RpcTransportError
from fake_node import FakeRpc

SPK_A = b"\x00\x14" + b"\xaa" * 20
SPK_B = b"\x00\x14" + b"\xbb" * 20
TXID = bytes(range(32))


@pytest.fixture
def rpc() -> FakeRpc:
    return FakeRpc()


@pytest.fixture
def supervisor(rpc):
    sup = ScanSupervisor(rpc, batch_window=0.05)
    sup.start()
    yield sup
    sup.close()


def wait(future, timeout=5.0):
    return future.result(timeout=timeout)


# ── baselining ──────────────────────────────────────────────────────────────────────────────


def test_a_scan_returns_the_coins_the_script_already_holds(rpc):
    """The whole point of a baseline: an address enrolled today usually already has coins, and
    they must be watched from the start rather than from the next time one moves."""
    rpc.unspents = {SPK_A: [(TXID, 0), (TXID, 7)]}
    with ScanSupervisor(rpc, batch_window=0.05) as sup:
        found = wait(sup.submit(SPK_A))

    assert [(u.txid, u.vout) for u in found] == [(TXID, 0), (TXID, 7)]
    assert all(u.spk == SPK_A for u in found)


def test_txids_come_back_in_internal_byte_order(rpc):
    """The RPC reports display order and the rest of the codebase works in internal order.
    Getting this wrong produces outpoints that look plausible and match nothing, forever."""
    rpc.unspents = {SPK_A: [(TXID, 0)]}
    with ScanSupervisor(rpc, batch_window=0.05) as sup:
        found = wait(sup.submit(SPK_A))
    assert found[0].txid == TXID
    assert found[0].txid != TXID[::-1]


def test_a_script_with_no_coins_yields_an_empty_baseline(rpc):
    """Not an error. A freshly generated cold address is the expected case."""
    with ScanSupervisor(rpc, batch_window=0.05) as sup:
        assert wait(sup.submit(SPK_A)) == ()


def test_the_descriptor_carries_the_script_not_an_address(rpc):
    """`raw(<hex>)` means no address encoding is constructed anywhere, so there is no address
    string in existence to be logged by the node or by us (invariant I1)."""
    with ScanSupervisor(rpc, batch_window=0.05) as sup:
        wait(sup.submit(SPK_A))

    start = next(c for c in rpc.calls if c[1] and c[1][0] == "start")
    assert start[1][1] == [f"raw({SPK_A.hex()})"]


# ── batching ────────────────────────────────────────────────────────────────────────────────


def test_requests_that_arrive_together_go_out_as_one_scan(rpc):
    """The cost is the UTXO-set walk, not the descriptor count. One scan per enrolment would
    cap the service at about nineteen an hour."""
    with ScanSupervisor(rpc, batch_window=0.1) as sup:
        futures = [sup.submit(bytes([i]) + SPK_A[1:]) for i in range(5)]
        for f in futures:
            wait(f)

    assert rpc.batch_sizes == [5]


def test_a_batch_is_capped(rpc):
    """Unbounded batches would trade one long pole for another, and a failed scan would take
    every queued enrolment down with it."""
    with ScanSupervisor(rpc, batch_max=3, batch_window=0.1) as sup:
        futures = [sup.submit(bytes([i]) + SPK_A[1:]) for i in range(7)]
        for f in futures:
            wait(f)

    assert max(rpc.batch_sizes) == 3
    assert sum(rpc.batch_sizes) == 7


def test_two_tenants_watching_one_script_cost_one_descriptor(rpc):
    """Addresses are not owned. Asking the node the same question twice costs real seconds for
    an identical answer."""
    rpc.unspents = {SPK_A: [(TXID, 3)]}
    with ScanSupervisor(rpc, batch_window=0.1) as sup:
        first, second = sup.submit(SPK_A), sup.submit(SPK_A)
        found_first, found_second = wait(first), wait(second)

    assert rpc.batch_sizes == [1]
    assert found_first == found_second
    assert [(u.txid, u.vout) for u in found_first] == [(TXID, 3)]


def test_each_script_gets_only_its_own_coins(rpc):
    """A batched scan returns one flat list. Mapping it back by script is the whole risk of
    batching — a mix-up hands one tenant another tenant's outpoints."""
    rpc.unspents = {SPK_A: [(TXID, 1)], SPK_B: [(TXID, 2), (TXID, 9)]}
    with ScanSupervisor(rpc, batch_window=0.1) as sup:
        a, b = sup.submit(SPK_A), sup.submit(SPK_B)
        found_a, found_b = wait(a), wait(b)

    assert [u.vout for u in found_a] == [1]
    assert [u.vout for u in found_b] == [2, 9]
    assert rpc.batch_sizes == [1] or rpc.batch_sizes == [2]


def test_an_unspent_for_a_script_nobody_asked_about_reaches_nobody(rpc):
    """A baseline containing a stranger's coin would arm an alarm on a spend the user has
    nothing to do with.

    Results are delivered by looking up each requested script, so an unrequested one has no
    recipient — the guard in the loop only keeps the dict from growing. The mutation that
    actually threatens this is "every request receives every coin the batch found", which
    `test_each_script_gets_only_its_own_coins` is the one to catch.
    """
    rpc.result_override = {
        "success": True,
        "unspents": [
            {"txid": TXID[::-1].hex(), "vout": 0, "scriptPubKey": SPK_A.hex()},
            {"txid": TXID[::-1].hex(), "vout": 1, "scriptPubKey": SPK_B.hex()},
        ],
    }
    with ScanSupervisor(rpc, batch_window=0.05) as sup:
        found = wait(sup.submit(SPK_A))
    assert [u.vout for u in found] == [0]


# ── serialisation ───────────────────────────────────────────────────────────────────────────


def test_scans_never_overlap(rpc):
    """bitcoind rejects a concurrent start. If the supervisor ever issued one, every enrolment
    behind it would fail for a reason that has nothing to do with the enrolment."""
    rpc.scan_duration = 0.05
    with ScanSupervisor(rpc, batch_max=1, batch_window=0.0) as sup:
        for f in [sup.submit(bytes([i]) + SPK_A[1:]) for i in range(4)]:
            wait(f)

    assert rpc.concurrent_start_attempts == 0
    assert rpc.batch_sizes == [1, 1, 1, 1]


def test_the_queue_is_bounded_and_says_so(rpc):
    """At ~186 s a scan, an unbounded queue is a promise of a wait nobody is told about.
    Refusing is the answer invariant I5 asks for."""
    rpc.scan_duration = 0.3
    with ScanSupervisor(rpc, queue_maxsize=2, batch_max=1, batch_window=0.0) as sup:
        accepted, refused = 0, 0
        for i in range(12):
            try:
                sup.submit(bytes([i]) + SPK_A[1:])
                accepted += 1
            except ScanQueueFull:
                refused += 1
        assert refused > 0, "a bounded queue that never refuses is not bounded"
        assert accepted >= 2


def test_pending_reports_the_backlog(rpc):
    """What a queued user's position is derived from — "you are third" needs a number."""
    rpc.scan_duration = 0.3
    with ScanSupervisor(rpc, batch_max=1, batch_window=0.0) as sup:
        for i in range(4):
            sup.submit(bytes([i]) + SPK_A[1:])
        time.sleep(0.05)
        assert sup.pending() >= 1


# ── the orphan, from every direction ────────────────────────────────────────────────────────


def test_shutdown_aborts_the_scan_in_flight(rpc):
    """The ordinary path — and the one a test can accidentally fail to check.

    Asserting only that the node stops scanning is not enough, and this test made exactly that
    mistake: a scan ends on its own eventually, so a supervisor that simply walked away passed
    by *outlasting* it. Two things have to be true instead — an abort was actually sent, and
    shutdown did not sit through the scan to get there. In production that difference is thirty
    seconds against three minutes of a container refusing to die.
    """
    rpc.scan_duration = 5.0
    sup = ScanSupervisor(rpc, batch_window=0.0)
    sup.start()
    aborts_before = rpc.aborts
    sup.submit(SPK_A)

    for _ in range(500):  # wait for the scan to actually be in flight
        if rpc.scan_running:
            break
        time.sleep(0.01)
    assert rpc.scan_running

    started = time.monotonic()
    sup.close()
    elapsed = time.monotonic() - started

    assert rpc.aborts > aborts_before, "closed without telling the node to stop scanning"
    assert elapsed < rpc.scan_duration / 2, "shutdown waited the scan out instead of aborting it"
    assert not rpc.scan_running, "closed the supervisor and left the node scanning"


def test_a_scan_left_running_by_a_previous_process_is_aborted_at_startup(rpc):
    """The path that cannot be intercepted. SIGKILL, an OOM kill and a power cut all leave a
    scan running with no chance to clean up, so the only complete answer is to ask on the way
    in rather than promise something on the way out."""
    def abandon_a_scan():
        # Raises when the client's patience runs out; the node keeps scanning. Swallowed here
        # because the abandonment *is* the setup, not a failure.
        with contextlib.suppress(RpcTransportError):
            rpc.call("scantxoutset", "start", [f"raw({SPK_A.hex()})"], timeout=0.05)

    rpc.scan_duration = 10.0
    orphan = threading.Thread(target=abandon_a_scan, daemon=True)
    orphan.start()
    orphan.join(timeout=5.0)
    for _ in range(200):
        if rpc.scan_running:
            break
        time.sleep(0.01)
    assert rpc.scan_running, "the fake did not leave an orphan to find"

    rpc.scan_duration = 0.0
    sup = ScanSupervisor(rpc, batch_window=0.0)
    sup.start()
    try:
        assert sup.orphans_aborted == 1
        assert not rpc.scan_running
    finally:
        sup.close()


def test_a_clean_start_reports_no_orphan(rpc):
    """The counter has to mean something. If it incremented every time, it would be noise."""
    sup = ScanSupervisor(rpc, batch_window=0.0)
    sup.start()
    sup.close()
    assert sup.orphans_aborted == 0


def test_close_is_idempotent(rpc):
    """`atexit` and an explicit call both fire. A shutdown path that raises on its second visit
    is a shutdown path that leaves a scan running."""
    sup = ScanSupervisor(rpc, batch_window=0.0)
    sup.start()
    sup.close()
    sup.close()


def test_a_timed_out_scan_call_leaves_an_orphan_the_client_cannot_see(rpc):
    """Documents the trap rather than a feature: abandoning the HTTP request does not stop the
    scan, so a read timeout below the scan duration *causes* the orphan it looks like it is
    avoiding. This is why `scan_timeout` defaults far above the measured ~186 s."""
    rpc.scan_duration = 5.0
    with pytest.raises(RpcTransportError):
        rpc.call("scantxoutset", "start", [f"raw({SPK_A.hex()})"], timeout=0.05)
    assert rpc.scan_running, "the node stopped scanning because a client hung up — it does not"

    rpc.call("scantxoutset", "abort")
    assert not rpc.scan_running


# ── failure ─────────────────────────────────────────────────────────────────────────────────


def test_a_rejected_scan_fails_its_whole_batch(rpc):
    """Every request in the batch depended on that one call. Leaving them pending forever would
    hang enrolment silently, which is the failure mode invariant I5 exists to forbid."""
    rpc.start_error = RpcError(-8, "Scan already in progress")
    with ScanSupervisor(rpc, batch_window=0.1) as sup:
        futures = [sup.submit(bytes([i]) + SPK_A[1:]) for i in range(3)]
        for f in futures:
            with pytest.raises(ScanFailed):
                wait(f)


def test_a_scan_failure_never_carries_the_script(rpc):
    """The node's message quotes the descriptor it rejected, and a descriptor contains a
    watched scriptPubKey. Invariant I1's usual trap is exception handlers, so the error stops
    at this boundary rather than travelling into a caller's log."""
    rpc.start_error = RpcError(-5, f"Invalid descriptor raw({SPK_A.hex()})")
    with ScanSupervisor(rpc, batch_window=0.05) as sup, pytest.raises(ScanFailed) as exc:
        wait(sup.submit(SPK_A))

    assert SPK_A.hex() not in str(exc.value)
    assert "aaaa" not in str(exc.value).lower()
    assert exc.value.code == -5


def test_an_unreachable_node_fails_the_batch_rather_than_hanging(rpc):
    rpc.start_error = RpcTransportError("scantxoutset: ConnectionRefusedError")
    with ScanSupervisor(rpc, batch_window=0.05) as sup, pytest.raises(ScanFailed):
        wait(sup.submit(SPK_A))


def test_a_malformed_result_is_a_failure_not_a_silent_empty_baseline(rpc):
    """An empty baseline is indistinguishable from "this address has no coins", so a garbled
    result must not be allowed to look like one — it would arm a watch over nothing."""
    rpc.result_override = {"success": True, "unspents": [{"vout": 0}]}
    with ScanSupervisor(rpc, batch_window=0.05) as sup, pytest.raises(ScanFailed):
        wait(sup.submit(SPK_A))


def test_an_unsuccessful_scan_is_a_failure(rpc):
    rpc.result_override = {"success": False, "unspents": []}
    with ScanSupervisor(rpc, batch_window=0.05) as sup, pytest.raises(ScanFailed):
        wait(sup.submit(SPK_A))


def test_queued_requests_fail_on_shutdown_rather_than_hanging(rpc):
    """Never fail silently: a caller waiting on a baseline that will now never happen has to be
    told, or the item sits in ARMING forever."""
    rpc.scan_duration = 0.4
    sup = ScanSupervisor(rpc, batch_max=1, batch_window=0.0)
    sup.start()
    futures = [sup.submit(bytes([i]) + SPK_A[1:]) for i in range(4)]
    time.sleep(0.05)
    sup.close()

    outcomes = []
    for f in futures:
        try:
            f.result(timeout=2.0)
            outcomes.append("ok")
        except ScanFailed:
            outcomes.append("failed")
        except concurrent.futures.TimeoutError:
            outcomes.append("still pending")

    assert "still pending" not in outcomes


def test_submitting_after_close_is_refused(rpc):
    sup = ScanSupervisor(rpc, batch_window=0.0)
    sup.start()
    sup.close()
    with pytest.raises(ScanFailed):
        sup.submit(SPK_A)


def test_starting_twice_is_a_programming_error(rpc):
    sup = ScanSupervisor(rpc, batch_window=0.0)
    sup.start()
    try:
        with pytest.raises(RuntimeError):
            sup.start()
    finally:
        sup.close()
