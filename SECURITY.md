# Security policy

This project is a security product, so the bar for its own security has to be the one it asks
its users to expect. That cuts both ways: reports are genuinely welcome, and some things that
look like findings are decisions made on purpose. Both are described below.

**Status: pre-alpha.** There is no hosted service and no release. `main` is the only branch
that exists to support.

---

## Reporting a vulnerability

Use **[GitHub's private vulnerability reporting](https://github.com/Wired4ncer/coldwatch/security/advisories/new)**.

Please do not open a normal issue for a security problem. Issues here are public the moment
they are filed, and for this project that is worse than usual: a flaw in the matching loop or
the storage layer is a flaw in other people's ability to notice their coins moving.

Useful reports say what property breaks, how to reproduce it, and what an attacker gets. A
proof of concept against the offline fixtures is ideal — see [CONTRIBUTING §2](CONTRIBUTING.md),
which is written so anyone can run the whole thing with no node, no credentials and no host
access.

**What to expect.** One maintainer, best effort, no bounty programme and no payment — said
plainly so nobody spends a week expecting one. An acknowledgement within **7 days**; if you
have heard nothing in **14**, assume it did not reach anyone and open a public issue asking for
contact *without* the details. A fix or a written explanation of why it will not be fixed
within **90 days**.

---

## What counts as a vulnerability here

**The invariants in [CONTRIBUTING §1](CONTRIBUTING.md) are the security model.** A change that
breaks one is a security bug even when it has no exploit in the usual sense, and reports of
that kind are wanted — they are also the ones most likely to go unreported, because they do not
look like vulnerabilities.

| Invariant | A report against it looks like |
|---|---|
| **I1** — a plaintext address exists only in request scope | Any path that writes an address to a log, a database column, an error message, a metric label or a stack trace. Exception handlers are the classic one. |
| **I2** — an alert carries a nickname, a chain and a status | An `Alert` reaching a renderer with an amount, a txid or anything derived from chain data. |
| **I3** — no event history at rest | Any persisted record of *when* something fired. Matched against the public chain, a handful of timestamps intersect to an address without anyone holding the HMAC key. |
| **I4** — the firehose is never the system of record | Any path that assumes it has seen every transaction. A silently dropped message is a missed alert, which is the failure this exists to prevent. |
| **I5** — never fail silently | Anything that can stop working while still appearing healthy. A watcher believed to be running is worse than none, because the user has stopped worrying. |

Also in scope, and ordinary: key handling and the HKDF/HMAC construction, the transaction
parser (it consumes attacker-influenced bytes), the matching and reconciliation logic, capability
token generation and lookup, and channel implementations — particularly anything that lets a
destination escape into a log or an error string.

---

## Not vulnerabilities

**Accepted residuals.** These are documented decisions, not oversights, and each is stated
publicly in [docs/architecture.md](docs/architecture.md) rather than buried:

- **A live compromise of the running service exposes the match set.** Only a trusted-execution
  design or a client-side application closes this, and both were rejected as out of scope.
- **The database plus the master key is full exposure.** The design goal is that the database
  *alone* is unmatchable noise; the key living elsewhere is what does that work.
- **Plaintext is seen transiently** at enrolment and at the moment an alert fires. This is
  irreducible for a hosted service, which is why it is written down instead of denied.
- **Outgoing alarms send instantly, so send-timing correlates with the public chain.** Speed is
  the product. This is why the claim is unlinkability and never "nobody can tell."
- **Email is a provider-reads channel** and is offered behind an explicit acknowledgement. That
  a mail provider can read a message it delivers is not a finding.
- **A lost capability token means lost service.** There is no recovery path, because a recovery
  path is an account, and an account is the thing this product does not have.
- **An alert reaches one relay from a single service-wide list, not the recipient's own
  relays.** `NostrChannel.send` stops at the first relay in `COLDWATCH_NOSTR_RELAYS` that ACKs
  the event; that list is not per-destination, and this channel does not fetch a recipient's
  `kind:10050` DM-relay list per NIP-17. If the recipient's client only reads from relays outside
  that list, a `DeliveryResult(ok=True)` alarm can still go unseen. Per-recipient relay discovery
  is not implemented yet.

If you think one of these is *worse than documented* — that a stated residual leaks more than
the document claims — that is a real report and worth sending.

**Also out of scope:** denial of service and traffic flooding; social engineering; physical
access; automated scanner output with no demonstrated impact; and dependency CVEs with no
reachable path.

**On dependencies.** This document previously said the runtime had no third-party dependencies
at all, then that it had exactly one. Both sentences were replaced rather than deleted, because
what they were really claiming — a supply chain small enough to read — is still the design goal
and should be checkable against reality, not preserved as a stale number.

The runtime now has **three** third-party dependencies, declared in
[`pyproject.toml`](pyproject.toml):

| Package | Why it is here | What it can reach |
|---|---|---|
| `pyzmq` | bitcoind publishes over ZMQ; there is no stdlib client, and reimplementing the wire protocol would be a worse risk than the dependency | Two localhost SUB sockets on our own node. It is handed no keys, no database, and no destinations. |
| `coincurve` | The Nostr channel's NIP-44 encryption needs secp256k1 ECDH and BIP340 Schnorr signing (`channels/nostr/nip44.py`, `nip01.py`). This is exactly the elliptic-curve arithmetic this project does not hand-roll — unlike the padding, HKDF, ChaCha20 and bech32 around it, which stayed stdlib and are checked against RFC/NIP test vectors in `tests/`. | The service's Nostr private key, held in memory only for the duration of a sign/ECDH call. Never the destination npub's private key — that is never in this process. |
| `websocket-client` | Relay publish is a WebSocket connection; there is no stdlib client, same reasoning as `pyzmq`. | One outbound `wss://` connection per configured relay, opened per send and closed immediately after. Verifies the server certificate and hostname by default — `channels/nostr/channel.py` also refuses to construct with a non-`wss://` relay URL, so there is no plaintext fallback to reach in the first place. |

Everything else is standard library on purpose, including the transaction parser — sixty lines
rather than a parsing library, because the hot path of a service whose pitch is that it holds
nothing worth stealing is a poor place for someone else's code. Development tooling (pytest,
ruff) is not runtime and is not in that count.

A dependency finding is therefore in scope if it is against `pyzmq`, `coincurve` or
`websocket-client` **and** you can describe the reachable path; otherwise it is almost certainly
about the development tooling.

---

## Testing

**There is no hosted service.** Nothing is deployed and nothing is accepting users. When that
changes, this section will say so — and testing against the live service will not be
authorised, because its users are people relying on an alert that fires once.

Everything worth testing runs offline today: `tools/replay_zmq.py` serves a recorded stream
over ZMQ, `tools/fake_rpc.py` stands in for the node, and the fixtures under `tests/fixtures/`
include a deliberately damaged stream. No infrastructure access is needed to find real bugs
here, which is deliberate.

---

## Disclosure

Coordinated. Report privately, we fix, then it gets published — including what went wrong,
because a project whose product is a privacy promise does not get to be quiet about breaking
one. You will be credited by whatever name you ask for, or not at all if you prefer.

If a report turns out to describe something already decided, you will get the reasoning and a
pointer to where it is written down, not a closed ticket.
