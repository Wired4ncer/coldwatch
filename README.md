# cold.watch

**A tripwire for cold storage.** Register a Bitcoin address you never expect to move. If it
ever moves, you get told immediately.

> **Status: pre-alpha.** Nothing is deployed and nothing is accepting users. This repository
> is the build; the service does not exist yet.

---

## What this is honestly for

If an attacker holds your seed, they hold every address derived from it, and a sweep is signed
and broadcast in one action. **You cannot out-race it.** For a single-address wallet, an alert
is notification of a loss, not a chance to prevent it.

Anyone promising otherwise is selling you something. Here is what a tripwire genuinely does:

1. **It saves your other seeds.** Attackers sweep sequentially. An alert on the first movement
   is time to evacuate everything held under different seeds or devices. If you have more than
   one wallet, this is the difference between losing one and losing all of them.
2. **It catches staged attacks** — a small test spend first, or one account before the rest.
3. **It tells you which seed is burned.** That is decisive information about what to move and
   what is still safe. Without it you are guessing under time pressure.
4. **It keeps the trail warm.** Detection latency is what turns a traceable theft into a cold
   one. Funds noticed in minutes can sometimes be followed and frozen; funds noticed in months
   generally cannot.

**The honest pitch:** *we tell you which seed is burned, in time to save the others, and while
the trail is still warm.*

## Design principles

These are constraints on the build, not marketing copy.

- **No accounts.** No email required, no phone, no username. Access is a random capability
  token. Lost token means lost service — that is the trade, and it is stated plainly.
- **Register and forget.** Watched targets are stored as keyed HMACs, never as plaintext
  addresses. A stolen database alone is unmatchable noise.
- **Minimal alerts.** An alert carries your own nickname for the watch, the chain, and the
  status. Never the address, never an amount, never a transaction id.
- **Own node, no third-party data.** Bitcoin support reads from our own node. No block explorer
  or data provider is told what is being watched, because none is asked.
- **Outgoing is an alarm, incoming is information.** Deposits to a cold address are not an
  emergency and must not be able to train you to ignore the alarm.
- **Never fail silently.** A watcher that has quietly stopped is worse than no watcher, because
  you believe you are covered. Balance running out is announced well ahead, and stopping is
  announced explicitly.
- **Prove it is alive.** Delivery is test-fired before a channel counts as working, and the
  service is watched by an independent process on separate infrastructure.

## Why open source

The product is a promise about what we do *not* collect. That promise is unverifiable if the
code is closed. Anyone can clone this — the architecture is not the moat and was never meant to
be. What cannot be cloned is a public track record.

## Status

| Component | State |
|---|---|
| Detection engine | design complete, build not started |
| Data source | verified working against the target node |
| Enrolment / payment / delivery | not started |
| Deployment | none |

## License

Not yet chosen. Until one is added, no rights are granted.
