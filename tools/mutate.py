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

⚠️ **This tool edits files in place and restores them afterwards.** It restores on exceptions,
on Ctrl-C, and on SIGTERM; if it is killed in a way it cannot intercept, the *next* run restores
what was left behind before doing anything else. Details under "Leaving a mutation behind" below.

## Leaving a mutation behind

A sweep is a loop that writes broken code to disk on purpose. The restore is the only thing
standing between that and a source tree quietly containing, say, a disabled key-length check —
which is what happened on 2026-08-09 and is why this section exists.

`try/finally` covers exceptions and Ctrl-C, and does **not** cover SIGTERM, which is what
`timeout` sends, what CI sends when a job is cancelled, and what most process supervisors send
first. A sweep run as `timeout 900 python tools/mutate.py` that hits its limit therefore left
the last mutation applied, silently, with no non-zero exit to notice — the shell reports 124 and
the tree looks fine until something fails much later for an unrelated-looking reason.

Two defences, in the order they matter:

1. **A handler for SIGTERM and SIGINT**, so the ordinary kill paths restore.
2. **A journal on disk**, written before each mutation and cleared after the restore. SIGKILL,
   an OOM kill and a power cut cannot be intercepted at all, so the only complete answer to
   "did a previous run leave something broken?" is to ask on the way *in*. That is the same
   reasoning as `node/supervisor.py`'s startup abort, for the same reason.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "coldwatch"

#: Records the file being mutated and its original contents, so a run that is killed outright
#: can be cleaned up by the next one. Deliberately inside the repo rather than in /tmp: a
#: journal that a reboot clears is a journal that fails exactly when it is needed.
JOURNAL = ROOT / ".mutate-journal.json"


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


#: The two loops of `Matcher.match`, quoted whole so they can be swapped cleanly. Long
#: anchors are a deliberate trade: if either loop is edited the sweep errors rather than
#: silently skipping, which forces whoever edited it to re-derive the equivalence argument
#: recorded against the swap below.
INPUTS_LOOP = """\
        for op in tx.inputs:  # empty for a coinbase: it spends nothing
            op_h = outpoint_hmac(self._k, op.txid, op.vout)
            # The record first, then the mempool-only coins. A spend of a deposit that has not
            # confirmed yet is still a spend, and it is the case the record cannot cover.
            for item_id in (
                *self._index.items_owning_outpoint(op_h),
                *self.provisional.items(op_h),
            ):
                if item_id not in outgoing:
                    outgoing.append(item_id)
"""

OUTPUTS_LOOP = """\
        for out in tx.outputs:
            spk_h = spk_hmac(self._k, out.spk)
            for item_id in self._index.items_watching_spk(spk_h):
                if item_id not in incoming:
                    incoming.append(item_id)
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
        old="""\
    preimage = (
        raw[start:end]
        if not has_witness
        else raw[start : start + 4] + raw[start + 6 : witness_start] + raw[locktime_start:end]
    )
""",
        new="    preimage = raw[start:end]\n",
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
        old='    if end != len(raw):\n        raise MalformedTransaction("trailing bytes after transaction")',
        new="    pass",
    ),
    Mutation(
        module="match/tx.py",
        describes="a transaction ends where the last one did, so a block reads the same one forever",
        old="    locktime_start = r.pos\n    r.uint32()  # locktime\n    end = r.pos",
        new="    locktime_start = r.pos\n    r.uint32()  # locktime\n    end = start",
    ),
    # ── block.py: the only thing that writes the record ─────────────────────────────────────
    Mutation(
        module="match/block.py",
        describes="a block whose transactions do not fill it is parsed anyway, partially",
        old='    if pos != len(raw):\n        # Trailing bytes mean the count was wrong or a transaction was misparsed, and either\n        # way the transactions we just read are not trustworthy as a set.\n        raise MalformedBlock("trailing bytes after the last transaction")',
        new="    pass",
    ),
    Mutation(
        module="match/block.py",
        describes="a block claiming zero transactions is a block",
        old='    if count == 0:',
        new="    if False:",
    ),
    Mutation(
        module="match/block.py",
        describes="the parent hash is read from the wrong header field",
        old="    prev_hash = header[4:36]",
        new="    prev_hash = header[36:68]",
    ),
    Mutation(
        module="match/block.py",
        describes="a transaction that will not parse is skipped, leaving the rest of the block",
        old="        except MalformedTransaction as exc:\n            raise MalformedBlock(f\"transaction {len(transactions)}: {exc}\") from None",
        new="        except MalformedTransaction:\n            break",
    ),
    # ── stream.py: the write rule itself ────────────────────────────────────────────────────
    Mutation(
        module="match/stream.py",
        describes="the mempool writes the record, so an unconfirmed receipt looks confirmed",
        old="        matches = self.matcher.match(tx)\n        # Arm what it pays to a watched script, in memory. Without this, a deposit spent again\n        # before it confirms would never be armed at all and the spend would alarm nobody.\n        self.matcher.note_unconfirmed(tx)",
        new="        matches = self.matcher.match(tx)\n        self.matcher.apply(tx)",
    ),
    Mutation(
        module="match/stream.py",
        describes="a deposit spent before it confirms is never armed, so the spend alarms nobody",
        old="        self.matcher.note_unconfirmed(tx)",
        new="        pass",
    ),
    Mutation(
        module="match/stream.py",
        describes="a block that will not parse is counted and forgotten",
        old="            self.tracker.flag_for_reconciliation()",
        new="            pass",
    ),
    Mutation(
        module="match/stream.py",
        describes="a confirmation re-alerts what the mempool already announced",
        old="            if self.seen.add(tx.txid):\n                alerts.extend(matches)\n            else:\n                self.suppressed += 1",
        new="            alerts.extend(matches)",
    ),
    Mutation(
        module="match/stream.py",
        describes="a block is applied to the record without being matched first, tx by tx",
        old="        for tx in block.transactions:\n            matches = self.matcher.match(tx)\n            self.matcher.apply(tx)",
        new="        for tx in block.transactions:\n            self.matcher.apply(tx)\n            matches = self.matcher.match(tx)",
    ),
    # ── matcher.py: the memory-only overlay ─────────────────────────────────────────────────
    Mutation(
        module="match/matcher.py",
        describes="the record keeps a duplicate of a coin the mempool armed, after it confirms",
        old="        self.provisional.forget(tx.txid)",
        new="        pass",
    ),
    Mutation(
        module="match/matcher.py",
        describes="a provisional coin is forgotten by the wrong key, so nothing is ever released",
        old="        self._drop(self._by_txid.pop(txid, ()))",
        new="        self._drop(self._by_txid.get(txid, ()))",
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
    # ── reconcile.py: the repair, and the failures it must not paper over ───────────────────
    Mutation(
        module="reconcile.py",
        describes="the height of every block is asked of the node instead of counted locally",
        old="            yield from self._advance(block, self.tip.height + 1)",
        new="            yield from self._advance(block, self._height_of(block))",
    ),
    Mutation(
        module="reconcile.py",
        describes="the follower uses getblockheader, which the node's whitelist forbids",
        old='            described = self._rpc.call("getblock", block_hash[::-1].hex(), 1)',
        new='            described = self._rpc.call("getblockheader", block_hash[::-1].hex())',
    ),
    Mutation(
        module="reconcile.py",
        describes="a block that does not follow the tip is applied anyway, gap and all",
        old="        if block.prev_hash == self.tip.hash:",
        new="        if True:",
    ),
    Mutation(
        module="reconcile.py",
        describes="catch-up fetches the gap but stops one block short of the tip",
        old="        for height in range(self.tip.height + 1, target):",
        new="        for height in range(self.tip.height + 1, target - 1):",
    ),
    Mutation(
        module="reconcile.py",
        describes="fetched blocks are applied newest first",
        old="            blocks.append(fetched)",
        new="            blocks.insert(0, fetched)",
    ),
    Mutation(
        module="reconcile.py",
        describes="a reorged-out tip is treated as an ordinary gap and chained through",
        old='        if not self._on_active_chain(self.tip.hash):\n            raise ReorgDetected("the last applied block is no longer on the active chain")',
        new="        pass",
    ),
    Mutation(
        module="reconcile.py",
        describes="fetched blocks are trusted by height without chaining them together",
        old='            if fetched.prev_hash != expected_parent:',
        new="            if False:",
    ),
    Mutation(
        module="reconcile.py",
        describes="a competing block one above the tip is applied as though it followed",
        old='        parent = blocks[-1].block_hash if blocks else self.tip.hash\n        if block.prev_hash != parent:',
        new="        parent = blocks[-1].block_hash if blocks else self.tip.hash\n        if blocks and block.prev_hash != parent:",
    ),
    Mutation(
        module="reconcile.py",
        describes="a block already applied is applied a second time",
        old="        if self._already_applied(block):",
        new="        if False:",
    ),
    Mutation(
        module="reconcile.py",
        describes="the tip advances to a block before it has been applied",
        old="    def _advance(self, block: Block, height: int) -> Iterator[Block]:\n        yield block\n        self.tip = ChainTip(hash=block.block_hash, height=height)",
        new="    def _advance(self, block: Block, height: int) -> Iterator[Block]:\n        self.tip = ChainTip(hash=block.block_hash, height=height)\n        yield block",
        survives=True,
        why=(
            "The generator is consumed by a `for` loop that applies each block as it is "
            "yielded, so the tip assignment happens after the caller has applied the previous "
            "block either way -- the reordering only moves it within the same suspension "
            "point. It would matter if a caller collected the generator into a list before "
            "applying anything, which is exactly why blocks_to_apply is a generator and is "
            "documented as one. A test could only catch this by asserting on tip state from "
            "inside a partially-consumed iteration, which asserts on the mechanism rather "
            "than on any behaviour a caller can observe."
        ),
    ),
    Mutation(
        module="match/stream.py",
        describes="a failed catch-up leaves the record behind with the flag cleared",
        old="            self.tracker.flag_for_reconciliation()\n            self.catch_up_failures += 1\n            raise",
        new="            self.tracker.reconciled()\n            self.catch_up_failures += 1\n            raise",
    ),
    Mutation(
        module="match/stream.py",
        describes="the reconciliation flag is cleared on the attempt rather than the result",
        survives=True,
        why=(
            "Equivalent, and worth recording because it looks like it should not be. Clearing "
            "the flag before the work still leaves every exit in the same state: the success "
            "path clears it again in the `else` branch, and the failure path re-raises it in "
            "`except`. Nothing reads the flag in between -- applying a block touches the "
            "matcher and the seen-set, never the tracker -- so no caller can observe the "
            "window. It becomes a real bug the moment anything inside the loop consults the "
            "flag, or the `except` narrows to a type that lets some failure through, which is "
            "why the ordering in the source is the safe one regardless."
        ),
        old="        try:\n            for due in self._expand(block):\n                alerts.extend(self._apply_block(due))",
        new="        try:\n            self.tracker.reconciled()\n            for due in self._expand(block):\n                alerts.extend(self._apply_block(due))",
    ),
    # ── subscribe.py: the live end ──────────────────────────────────────────────────────────
    Mutation(
        module="subscribe.py",
        describes="one socket for both topics, so a 1.7 MB block queues in front of the stream",
        old='        socket.setsockopt(zmq.SUBSCRIBE, topic)',
        new='        socket.setsockopt(zmq.SUBSCRIBE, b"")',
    ),
    Mutation(
        module="subscribe.py",
        describes="the receive buffer is left at the ZMQ default the loss was measured under",
        old="        socket.setsockopt(zmq.RCVHWM, rcvhwm)",
        new="        socket.setsockopt(zmq.RCVHWM, 1000)",
    ),
    Mutation(
        module="subscribe.py",
        describes="transactions are drained before the blocks that arm the coins they spend",
        old="        for socket in (self._block, self._tx):",
        new="        for socket in (self._tx, self._block):",
    ),
    Mutation(
        module="subscribe.py",
        describes="the sequence counter is read from the payload part",
        old="        topic, body, seq = parts",
        new="        topic, seq, body = parts",
    ),
    Mutation(
        module="subscribe.py",
        describes="an envelope with no counter is passed on as though it could be checked",
        old="        if len(parts) != TOPIC_PARTS:\n            self.malformed_envelopes += 1\n            return None",
        new="        if len(parts) != TOPIC_PARTS:\n            parts = [*parts, b\"\\x00\" * 4][:3]",
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
    # ── channels/email.py: the privacy posture of the first delivery rail ───────────────────
    Mutation(
        module="channels/email.py",
        describes="the subject line varies with the alert, becoming a side channel",
        old='        message["Subject"] = SUBJECT',
        new='        message["Subject"] = SUBJECT if alert.kind is not AlertKind.MOVEMENT '
        'else f"{SUBJECT}: {alert.kind.value}"',
    ),
    Mutation(
        module="channels/email.py",
        describes="a permanent SMTP failure (5xx) is retried as though it were transient",
        old="            retriable = exc.smtp_code < 500",
        new="            retriable = True",
    ),
    Mutation(
        module="channels/email.py",
        describes="a malformed SMTP reply (code -1) is treated as a permanent failure",
        old="            retriable = exc.smtp_code < 500",
        new="            retriable = 400 <= exc.smtp_code < 500",
    ),
    Mutation(
        module="channels/email.py",
        describes="a server that refuses every AUTH mechanism is retried forever",
        old="""\
        except smtplib.SMTPNotSupportedError as exc:
            # Raised by login() when the server offers none of the AUTH mechanisms it knows.
            # That is a permanent configuration mismatch, not a subclass of
            # SMTPResponseException, and retrying cannot make the server support AUTH.
            return DeliveryResult(ok=False, retriable=False, detail=type(exc).__name__)
""",
        new="",
    ),
    Mutation(
        module="channels/email.py",
        describes="the destination leaks into the log-facing detail on a recipient refusal",
        old='            return DeliveryResult(ok=False, retriable=False, detail="recipient refused")',
        new='            return DeliveryResult(ok=False, retriable=False, detail=f"recipient refused: {dest}")',
    ),
    Mutation(
        module="channels/email.py",
        describes="validate_dest stores whatever case the user typed instead of a canonical form",
        old="        return candidate.lower()",
        new="        return candidate",
    ),
    Mutation(
        module="channels/email.py",
        describes="a movement with no direction renders as a reassuring deposit notice",
        old="        if alert.direction is Direction.INCOMING:",
        new="        if alert.direction is not Direction.OUTGOING:",
    ),
    # ── channels/nostr/channel.py: the relay boundary, where the reply is hostile input ──────
    #
    # Both of these are review findings from #35, and both have the same shape: an exception
    # escaping `send`. That is worse than any verdict `send` could return, because the caller
    # expected a `DeliveryResult` and gets an unhandled alarm instead -- and the loop never
    # reaches the relays listed after the one that threw.
    Mutation(
        module="channels/nostr/channel.py",
        describes="a relay reply that is bytes rather than text escapes send() as an exception",
        old="""\
                    frame = json.loads(conn.recv())
                except ValueError:""",
        new="""\
                    frame = json.loads(conn.recv())
                except json.JSONDecodeError:""",
    ),
    Mutation(
        module="channels/nostr/channel.py",
        describes="a relay URL that isn't a URL is accepted at construction and throws at 3am",
        old="""\
                raise ValueError(f"relay must be wss://: {relay!r}")
            _check_relay_url(relay)""",
        new="""\
                raise ValueError(f"relay must be wss://: {relay!r}")""",
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


def recover() -> str | None:
    """Restore whatever a killed run left mutated. Returns the path, or None if nothing was.

    Runs before the sweep does anything else. A journal that is only read on the way out is a
    journal that never runs in the case it exists for.
    """
    if not JOURNAL.exists():
        return None
    try:
        record = json.loads(JOURNAL.read_text())
        Path(record["path"]).write_text(record["original"])
    except (OSError, ValueError, KeyError):
        # Say so rather than continue: an unreadable journal means a file may still be broken,
        # and a sweep starting from a broken tree measures nothing.
        raise SystemExit(
            f"{JOURNAL} exists but could not be read. A previous run may have left a mutation "
            f"applied — check `git diff src/` before running again."
        ) from None
    JOURNAL.unlink(missing_ok=True)
    return record["path"]


def _install_restore_on_signal() -> None:
    """Restore on SIGTERM and SIGINT.

    SIGTERM is the one that matters: `timeout` sends it, CI sends it on cancellation, and
    Python's `finally` does not run for it. SIGKILL is deliberately absent because it cannot be
    caught — that is what the journal is for.
    """

    def handler(signum, frame):
        recover()
        # _exit rather than sys.exit: an exception here would unwind through the pytest
        # subprocess call and could be swallowed, leaving the file broken after all.
        os._exit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, handler)


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

    # Journal first, then mutate. The other order has a window in which the file is broken and
    # nothing on disk records how to put it back — which is the whole failure being fixed.
    JOURNAL.write_text(json.dumps({"path": str(path), "original": original}))
    try:
        path.write_text(mutated)
        passed, failing = run_pytest()
    finally:
        path.write_text(original)
        JOURNAL.unlink(missing_ok=True)
    return Result(mutation, caught=not passed, failing=failing)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--filter", default="", help="only mutations whose module or text matches")
    ap.add_argument("--list", action="store_true", help="list mutations and exit")
    args = ap.parse_args()

    recovered = recover()
    if recovered is not None:
        print(f"restored {recovered} — a previous run was killed mid-mutation\n")
    _install_restore_on_signal()

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
