#!/usr/bin/env python3
"""Break the code on purpose and require the tests to notice.

    python tools/mutate.py                 # run the whole sweep
    python tools/mutate.py --list          # show the mutations without running them
    python tools/mutate.py --filter gap    # only mutations whose text matches

A passing test suite says the code does something. It does not say the tests would *object* if
the code did the wrong thing instead — and a test that cannot object is a green tick with
nothing behind it. CONTRIBUTING §3 puts it as a rule: make the failure happen, then fix it. A
reconciliation loop that has never caught anything is not known to work, and neither is a test
that has never failed.

So each mutation below is a specific, plausible wrong implementation — an off-by-one in a gap
size, a txid hashed without stripping the witness, a flag cleared a moment too early. Applying
it must turn the suite red. If it does not, the mutation names a real gap in the tests, and the
fix is a test rather than a change here.

This is not a substitute for writing tests first; it answers a different question. Writing a
test first proves it fails when the code is *absent*. This proves it fails when the code is
*plausibly wrong*, which is the failure mode that actually ships.

⚠️ **This tool edits files in place and restores them afterwards.** It restores on crash and on
Ctrl-C too, but do not run it with unsaved work in `src/coldwatch/match/`.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "coldwatch"


@dataclass(frozen=True)
class Mutation:
    """One deliberate breakage, and what the suite is expected to do about it."""

    module: str
    """Path under `src/coldwatch/`, e.g. `match/tx.py`."""
    describes: str
    """What the mutation makes the code believe. Phrased as the wrong behaviour, not as a diff."""
    old: str
    new: str
    survives: bool = False
    """True for a mutation that is *expected* to pass the suite — see `why`."""
    why: str = ""
    """Required when `survives`: the argument for why the change is behaviour-preserving.

    An equivalent mutant is a finding, not an embarrassment. Recording it stops the same
    "missing test" from being rediscovered every few months, and if the suite ever *does* catch
    it, the behaviour has changed and the argument below needs re-deriving. So a surviving
    mutation that starts being caught fails this tool just as loudly as the reverse.
    """


#: The two loops of `Matcher.process`, quoted whole so they can be swapped cleanly. Long
#: anchors are a deliberate trade: if either loop is edited the sweep errors rather than
#: silently skipping, which forces whoever edited it to re-derive the equivalence argument
#: recorded against the swap below.
INPUTS_LOOP = """\
        for op in tx.inputs:  # empty for a coinbase: it spends nothing
            op_h = outpoint_hmac(self._k, op.txid, op.vout)
            for item_id in tuple(self._index.items_owning_outpoint(op_h)):
                if item_id not in outgoing:
                    outgoing.append(item_id)
                self._index.drop_outpoint(item_id, op_h)
"""

OUTPUTS_LOOP = """\
        for out in tx.outputs:
            spk_h = spk_hmac(self._k, out.spk)
            items = self._index.items_watching_spk(spk_h)
            if not items:
                continue
            new_op = outpoint_hmac(self._k, tx.txid, out.vout)
            for item_id in items:
                if item_id not in incoming:
                    incoming.append(item_id)
                # Tracked regardless of the item's alert mode: `mute` suppresses the
                # notification, not the bookkeeping. A muted deposit that never entered the
                # UTXO set would be a spend we could not see later.
                self._index.add_outpoint(item_id, new_op)
"""


MUTATIONS: list[Mutation] = [
    # ── sequence.py: the gap detector is the tripwire on the tripwire ───────────────────────
    Mutation(
        module="match/sequence.py",
        describes="a gap is one message larger than it is",
        old="            missing = delta - 1",
        new="            missing = delta",
    ),
    Mutation(
        module="match/sequence.py",
        describes="reconciliation is no longer needed once one clean message arrives",
        old="        if delta == 1:\n            return None",
        new="        if delta == 1:\n            self._needs_reconciliation = False\n            return None",
    ),
    Mutation(
        module="match/sequence.py",
        describes="a counter wrap is a gap of four billion messages",
        old="        elif last >= UINT32 - WRAP_MARGIN and seq < WRAP_MARGIN:",
        new="        elif False:",
    ),
    Mutation(
        module="match/sequence.py",
        describes="the first message on a topic implies everything before it was lost",
        old="        if last is None:\n            return None",
        new="        if last is None:\n            last = 0",
    ),
    Mutation(
        module="match/sequence.py",
        describes="a duplicated message counts as a lost one",
        old="        if delta == 0:\n            state.duplicates += 1",
        new="        if delta == 0:\n            state.missing_total += 1\n            state.duplicates += 1",
    ),
    Mutation(
        module="match/sequence.py",
        describes="a publisher restart needs no reconciliation",
        old="            state.restarts += 1\n            self._needs_reconciliation = True",
        new="            state.restarts += 1",
    ),
    Mutation(
        module="match/sequence.py",
        describes="every topic shares one sequence counter",
        old="        state = self._topics[topic]",
        new='        state = self._topics["shared"]',
    ),
    # ── tx.py: it parses bytes we do not control ────────────────────────────────────────────
    Mutation(
        module="match/tx.py",
        describes="a txid is the hash of the raw bytes, witness included",
        old="    preimage = raw if not has_witness else raw[:4] + raw[6:witness_start] + raw[-4:]",
        new="    preimage = raw",
    ),
    Mutation(
        module="match/tx.py",
        describes="a coinbase input is a spend like any other",
        old="        inputs=() if is_coinbase else tuple(inputs),",
        new="        inputs=tuple(inputs),",
    ),
    Mutation(
        module="match/tx.py",
        describes="every output believes it is at index zero",
        old="    for vout in range(n_out):",
        new="    for vout in [0] * n_out:",
    ),
    Mutation(
        module="match/tx.py",
        describes="bytes left over after the last field are fine",
        old='    if r.pos != len(raw):\n        raise MalformedTransaction("trailing bytes after transaction")',
        new="    pass",
    ),
    # ── keys.py: the keyed hashes are the privacy claim ─────────────────────────────────────
    Mutation(
        module="match/keys.py",
        describes="scriptPubKeys and outpoints are hashed in the same domain",
        old='    return hmac.new(key, tag + b"\\x00" + payload, hashlib.sha256).digest()',
        new="    return hmac.new(key, payload, hashlib.sha256).digest()",
    ),
    Mutation(
        module="match/keys.py",
        describes="an outpoint uses the display byte order",
        old='    return txid + struct.pack("<I", vout)',
        new='    return txid[::-1] + struct.pack("<I", vout)',
    ),
    Mutation(
        module="match/keys.py",
        describes="a coin is identified by its txid alone, ignoring which output it is",
        old="    return _tagged(k_match, TAG_OUTPOINT, canonical_outpoint(txid, vout))",
        new="    return _tagged(k_match, TAG_OUTPOINT, txid)",
    ),
    Mutation(
        module="match/keys.py",
        describes="both subkeys derive from the same info string",
        old="        store=hkdf(master, INFO_STORE),",
        new="        store=hkdf(master, INFO_MATCH),",
    ),
    Mutation(
        module="match/keys.py",
        describes="a master secret of any length is acceptable",
        old="    if len(master) < MIN_MASTER_BYTES:",
        new="    if False:",
    ),
    # ── matcher.py: the compare-and-update loop ─────────────────────────────────────────────
    Mutation(
        module="match/matcher.py",
        describes="a coin arriving at a watched script is not tracked",
        old="                self._index.add_outpoint(item_id, new_op)",
        new="                pass",
    ),
    Mutation(
        module="match/matcher.py",
        describes="a spent coin stays in the live set forever",
        old="                self._index.drop_outpoint(item_id, op_h)",
        new="                pass",
    ),
    Mutation(
        module="match/matcher.py",
        describes="one item is reported once per matching output rather than once",
        old="                if item_id not in incoming:\n                    incoming.append(item_id)",
        new="                incoming.append(item_id)",
    ),
    Mutation(
        module="match/matcher.py",
        describes="informational matches are reported ahead of alarms",
        old=(
            "            [Match(i, Direction.OUTGOING) for i in outgoing]\n"
            "            + [Match(i, Direction.INCOMING) for i in incoming]"
        ),
        new=(
            "            [Match(i, Direction.INCOMING) for i in incoming]\n"
            "            + [Match(i, Direction.OUTGOING) for i in outgoing]"
        ),
    ),
    # ── stream.py: the seam between a source and the loop ───────────────────────────────────
    Mutation(
        module="match/stream.py",
        describes="one unparseable message takes the whole loop down",
        old="        except MalformedTransaction:\n            self.malformed += 1\n            return ()",
        new="        except MalformedTransaction:\n            raise",
    ),
    Mutation(
        module="match/stream.py",
        describes="topics we do not decode have their sequence numbers ignored",
        old="        anomaly = self.tracker.observe(message.topic, message.seq)",
        new=(
            "        anomaly = (self.tracker.observe(message.topic, message.seq)\n"
            "                   if message.topic == TOPIC_TX else None)"
        ),
    ),
    Mutation(
        module="match/stream.py",
        describes="anomalies are counted but never announced to the caller",
        old="        if anomaly is not None and self._on_anomaly is not None:",
        new="        if False:",
    ),
    # ── node/rpc.py: it holds the credentials and reads the node's own words ────────────────
    Mutation(
        module="node/rpc.py",
        describes="an rpc error stringifies to the node's message, descriptor and all",
        old='        # Deliberately not the node\'s message: this string lands in logs and tracebacks.\n        return f"rpc error {self.code}"',
        new="        return self.message",
    ),
    Mutation(
        module="node/rpc.py",
        describes="repr includes the credentials",
        old='        return f"{type(self).__name__}({self._host}:{self._port})"',
        new='        return f"{type(self).__name__}({self._host}:{self._port} {self._auth})"',
    ),
    Mutation(
        module="node/rpc.py",
        describes="an error body is ignored, so a rejected call looks successful",
        old='        error = payload.get("error")',
        new="        error = None",
    ),
    # ── node/supervisor.py: every path here owes the node an abort ──────────────────────────
    Mutation(
        module="node/supervisor.py",
        describes="a scan left running by a dead process is not aborted at startup",
        old="        if self._abort_scan():\n            self.orphans_aborted += 1",
        new="        if False:\n            self.orphans_aborted += 1",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="shutdown walks away from the scan in flight",
        old="        if self._scan_in_flight.is_set():",
        new="        if False:",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="the queue is unbounded, so enrolment promises a wait nobody is told about",
        old="queue.Queue(maxsize=queue_maxsize)",
        new="queue.Queue()",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="queued requests are abandoned rather than failed on shutdown",
        old='        self._drain_queue(ScanFailed("supervisor shut down"))',
        new="        pass",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="a batch grows past its cap",
        old="        while len(batch) < self.batch_max:\n            try:\n                item = self._queue.get_nowait()",
        new="        while True:\n            try:\n                item = self._queue.get_nowait()",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="one descriptor per request, so a shared script is scanned twice",
        old="        descriptors = [f\"raw({spk.hex()})\" for spk in by_spk]",
        new="        descriptors = [f\"raw({r.spk.hex()})\" for r in live]",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="every request in a batch receives every coin the batch found",
        old=(
            "        for spk, requests in by_spk.items():\n"
            "            outcome = tuple(found[spk])\n"
            "            for request in requests:\n"
            "                request.future.set_result(outcome)"
        ),
        new=(
            "        everything = tuple(u for coins in found.values() for u in coins)\n"
            "        for requests in by_spk.values():\n"
            "            for request in requests:\n"
            "                request.future.set_result(everything)"
        ),
    ),
    Mutation(
        module="node/supervisor.py",
        describes="scan results keep the display byte order the RPC hands back",
        old='                    txid=bytes.fromhex(entry["txid"])[::-1],  # RPC gives display order',
        new='                    txid=bytes.fromhex(entry["txid"]),',
    ),
    Mutation(
        module="node/supervisor.py",
        describes="a scan failure carries the node's message, and the descriptor in it",
        old='            self._fail(live, ScanFailed("node rejected the scan", exc.code))',
        new="            self._fail(live, ScanFailed(exc.message, exc.code))",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="a malformed result entry is skipped, leaving a short baseline that looks real",
        old=(
            "            except (KeyError, ValueError, TypeError):\n"
            '                self._fail(live, ScanFailed("scan result was malformed"))\n'
            "                return"
        ),
        new="            except (KeyError, ValueError, TypeError):\n                continue",
    ),
    Mutation(
        module="node/supervisor.py",
        describes="an unsuccessful scan is read as an empty baseline",
        old='        if not isinstance(result, dict) or not result.get("success"):',
        new="        if False:",
    ),
    # ── known equivalent mutant ─────────────────────────────────────────────────────────────
    Mutation(
        module="match/matcher.py",
        describes="outputs are matched before inputs",
        survives=True,
        why=(
            "The two loops touch disjoint outpoints. An input references some earlier "
            "transaction; an output is keyed by this transaction's txid; and no transaction can "
            "spend an output it is itself creating. So the drops and the adds cannot interact "
            "and the loop order does not affect the UTXO set. The order that *is* observable is "
            "the order matches are reported, and that is fixed by the return statement — which "
            "the 'informational matches ahead of alarms' mutation above does cover."
        ),
        old=INPUTS_LOOP + "\n" + OUTPUTS_LOOP,
        new=OUTPUTS_LOOP + "\n" + INPUTS_LOOP,
    ),
]


@dataclass
class Result:
    mutation: Mutation
    caught: bool
    failing: list[str] = field(default_factory=list)
    error: str = ""


def run_pytest() -> tuple[bool, list[str]]:
    """Returns (passed, names of failing tests)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,  # a red suite is the expected outcome here, not an error
    )
    # "FAILED tests/test_sequence.py::test_a_single_drop_is_reported - assert ..."
    failing = [
        line.split()[1].split("::")[-1]
        for line in proc.stdout.splitlines()
        if line.startswith("FAILED") and len(line.split()) > 1
    ]
    return proc.returncode == 0, failing


def apply(mutation: Mutation, original: str) -> str | None:
    """Returns the mutated source, or None if it cannot be applied."""
    if mutation.old not in original:
        return None
    return original.replace(mutation.old, mutation.new, 1)


def evaluate(mutation: Mutation) -> Result:
    path = SRC / mutation.module
    original = path.read_text()

    mutated = apply(mutation, original)
    if mutated is None:
        # A stale anchor must be loud. Skipping it quietly would leave the sweep reporting
        # success while testing one thing fewer every time the code is refactored — the exact
        # shape of failure invariant I5 is about.
        return Result(mutation, caught=False, error="anchor not found; the mutation is stale")
    if mutated == original:
        return Result(mutation, caught=False, error="mutation changes nothing")
    try:
        ast.parse(mutated)
    except SyntaxError as exc:
        # Without this check a malformed mutant fails collection, the suite goes red, and the
        # mutation is scored as caught — proving only that Python rejects bad syntax.
        return Result(mutation, caught=False, error=f"mutant is not valid Python: {exc}")

    try:
        path.write_text(mutated)
        passed, failing = run_pytest()
    finally:
        path.write_text(original)
    return Result(mutation, caught=not passed, failing=failing)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--filter", default="", help="only mutations whose module or text matches")
    ap.add_argument("--list", action="store_true", help="list mutations and exit")
    args = ap.parse_args()

    selected = [
        m
        for m in MUTATIONS
        if args.filter.lower() in f"{m.module} {m.describes}".lower()
    ]
    if not selected:
        print(f"no mutations match {args.filter!r}")
        return 1

    if args.list:
        for m in selected:
            marker = "~" if m.survives else " "
            print(f"{marker} {m.module:<14} {m.describes}")
        print(f"\n{len(selected)} mutations (~ = expected to survive)")
        return 0

    # Mutating a suite that is already red proves nothing: every mutation would be scored as
    # caught by the failure that was there before the sweep started.
    print("baseline: ", end="", flush=True)
    passed, failing = run_pytest()
    if not passed:
        print("FAILED\n")
        print("The suite is red before any mutation was applied, so this sweep cannot")
        print("measure anything. Fix these first:")
        for name in failing:
            print(f"  {name}")
        return 1
    print("green\n")

    results = [evaluate(m) for m in selected]

    for r in results:
        m = r.mutation
        if r.error:
            status = "ERROR  "
        elif r.caught == (not m.survives):
            status = "surviv." if m.survives else "caught "
        else:
            status = "MISSED!" if not m.survives else "CAUGHT!"
        print(f"{status} {m.module:<14} {m.describes}")
        if r.error:
            print(f"         {r.error}")
        elif r.caught and r.failing:
            shown = ", ".join(r.failing[:3])
            print(f"         by {shown}{' …' if len(r.failing) > 3 else ''}")

    problems = [r for r in results if r.error or r.caught != (not r.mutation.survives)]
    expected_survivors = sum(1 for r in results if r.mutation.survives and not r.error)
    print(
        f"\n{len(results) - len(problems)}/{len(results)} as expected "
        f"({expected_survivors} known equivalent)"
    )

    for r in problems:
        m = r.mutation
        print()
        if r.error:
            print(f"ERROR  {m.module}: {m.describes}\n       {r.error}")
        elif not r.caught:
            print(
                f"MISSED {m.module}: {m.describes}\n"
                "       The suite accepted this. That is a missing test, not a mutation to\n"
                "       delete — unless you can argue the change is behaviour-preserving, in\n"
                "       which case mark it survives=True and write the argument in `why`."
            )
        else:
            print(
                f"CAUGHT {m.module}: {m.describes}\n"
                "       This was expected to survive. Behaviour changed, so the equivalence\n"
                "       argument in `why` no longer holds and needs re-deriving:\n"
                f"       {m.why}"
            )

    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
