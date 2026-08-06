# Contributing to cold.watch

Read this before your first pull request. Most of it is short. The **invariants** section is
the part that matters, because the privacy properties of this service are not emergent — they
survive only as long as every change respects them, and they are easy to break by accident
while writing perfectly reasonable code.

---

## 1. The invariants

These are not style preferences. A change that violates one is wrong even if it passes every
test, and the review will say so. If you think one needs to change, that is a design discussion
in an issue first — not a pull request.

### I1. A plaintext address exists only in request scope

An address arrives in an enrolment request, is converted to a scriptPubKey, is HMAC'd, and is
then gone. It is never written to the database, a log line, a queue, an error message, a metric
label, or a stack trace.

> **The trap:** exception handlers. A traceback that includes the request body defeats this
> entirely, and it will not show up in normal testing because nothing throws in the happy path.
> Use structured logging with an **allowlist** of loggable fields. Never a denylist — a denylist
> fails open every time someone adds a field.

### I2. An alert carries a nickname, a chain, and a status. Nothing else.

No address. No amount. No transaction id. No block height. The `Alert` dataclass is frozen and
deliberately does not carry those fields, so a renderer physically cannot leak what it never
receives. **Do not add fields to it "for context."** If a template needs something the dataclass
lacks, that is the signal to stop and open an issue.

### I3. No event history at rest

There is no `events` table and there must not be one. A stored row saying "item 47 fired at
14:32:07" is a timing side channel: matched against public chain data, two or three such rows
intersect to the exact address without anyone needing the HMAC key. The outbox holds a row only
while a delivery is in flight, and the row is deleted on completion — including on permanent
failure.

Timestamps that must persist are stored at **day precision**.

### I4. The firehose is never the system of record

The ZMQ stream drops messages silently under load — measured, not theoretical: ~832 transactions
lost across 3 sequence gaps in a 40-minute window, with no error raised, because ZMQ discards at
the high-water mark. A dropped transaction is a missed alert, which is the one failure this
product exists to prevent.

Therefore: the stream is a **latency optimisation**. Correctness comes from periodic
reconciliation against the UTXO set, which repairs misses rather than reporting them. Any code
path that assumes it has seen every transaction is a bug.

Track the ZMQ sequence number per topic and alert on a gap. It is the only in-band evidence a
drop occurred.

### I5. Never fail silently

A watcher believed to be running, that is not, is worse than no watcher — the user has stopped
worrying. Every stop is announced: balance running low, balance exhausted, watch stopped. A
delivery channel is not considered working until a test-fire has been confirmed by the user.

### I6. Secrets never enter the repository

The master key lives outside the database and outside the repo. Check `.gitignore` before adding
any config file. See §4 — **this repository is public, and its history is permanent.**

---

## 2. Development without infrastructure access

You do not need a Bitcoin node, credentials, or access to any host to build or test anything in
this repository. That is deliberate.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt        # pyzmq, for the stream replay
```

Then:

```bash
# Serve a recorded transaction stream over ZMQ, exactly as bitcoind would
python tools/replay_zmq.py tests/fixtures/stream-sample.jsonl --port 28333

# Same, but with a deliberate sequence gap so the gap detector is exercised
python tools/replay_zmq.py tests/fixtures/with-gap.jsonl --port 28333

# A fake bitcoind RPC, including a realistic slow scantxoutset
python tools/fake_rpc.py --port 18332 --scan-delay 186
```

**On `--scan-delay 186`:** that is the real measured duration of a `scantxoutset` against the
production node, not a pessimistic guess. The scan walks the entire UTXO set (~166M outputs), so
it does not get faster with a better-chosen address, and it grows over time. Enrolment must be
asynchronous, scans serialise (bitcoind runs one at a time), and an abandoned scan **keeps
running server-side** unless explicitly aborted. Test against the real number.

---

## 3. Workflow

- Branch from `main`. Name it `area/short-description`.
- One logical change per pull request. A PR that reorganises while it fixes is hard to review and
  harder to revert.
- Tests for anything with a failure mode. Especially: make the failure happen, then fix it. A
  reconciliation loop that has never caught anything is not known to work.
- `CODEOWNERS` routes privacy-critical paths to a second reader. That is not distrust; it is the
  same reason surgeons count instruments.

**Commit messages:** explain why, not what. The diff already says what.

---

## 4. This repository is public

It went public on 2026-08-06. There is no staging period and no grace window: **the moment you
push, it is published.** Git history is permanent — a secret committed and removed in a later
commit is still in the history, still fetchable, and still there years later.

So there is nothing to "treat as though" — every commit *is* public:

- No real addresses in tests or fixtures. Generate them, or use documented test vectors.
- No hostnames, IP addresses, usernames, or infrastructure details — not in code, not in
  comments, not in fixture filenames.
- No credentials, obviously, but also no credential *shapes* — a redacted example that reveals
  the format is still a hint.
- Nothing about the origin case beyond what the public site already says. The thesis is public;
  the specifics belong to someone else and are not ours to publish.

**Issues and pull request comments are public too.** This is the surface people forget, because
a clean `git log` says nothing about what is written in a comment thread. Two consequences:

- Planning and decision-making that touches anything sensitive does not belong in an issue here.
- **Editing is not redaction.** GitHub keeps edit history on issue bodies and comments, visible to
  anyone who can read them. To actually remove something you must *delete* the comment or issue.

One more, learned the hard way: **a safety note is content too, and it carries the shape of what it
protects.** Writing "never mention X" into a public artifact mentions X. If a rule only makes sense
by describing the thing it is protecting, the rule belongs somewhere private and the public version
should state the instruction without the referent.

If a secret does get committed, say so immediately — the fix is history rewriting plus rotating
whatever leaked, and both get harder the longer they wait.
