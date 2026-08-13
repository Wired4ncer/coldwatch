# Architecture

The build plan. Read [CONTRIBUTING.md](../CONTRIBUTING.md) §1 first — the invariants there are
constraints on everything below.

**Stack:** Python + SQLite (WAL) + Docker Compose. One service box, plus an independent watchdog
on separate infrastructure.

---

## 1. Key material

One **master secret** lives outside the database — environment variable or systemd
`LoadCredential` — and never on the same backup media as the database. Two subkeys via HKDF:

```
k_match = HKDF(master, "coldwatch/match/v1")   # keyed HMAC for watch targets
k_store = HKDF(master, "coldwatch/store/v1")   # AEAD for labels and channel destinations
```

Two keys rather than one because their exposure profiles differ: `k_match` is needed constantly
in the hot matching loop, `k_store` only at enrolment, alert-fire, and dashboard render.

**Threat model:**

| Attacker has | Outcome |
|---|---|
| The database alone | Unmatchable noise. Addresses are HMAC'd under a key that isn't there. |
| Database **and** master key | Full exposure of watch targets. |
| Live compromise of the running service | Full exposure. Accepted residual, stated publicly. |

**HMAC the scriptPubKey, not the address string** — canonical form kills encoding aliases, and
it is what the stream gives us anyway. For spend detection, additionally HMAC **outpoints**
(`txid:vout`, canonically serialised).

> **Why HMAC and not a plain hash.** Addresses come from a public, enumerable set. Anyone holding
> `SHA256(address)` can hash the chain's entire address set and match. Hashing protects secrets;
> an address is not a secret. The key is what makes the storage unmatchable.

---

## 2. Enrolment

```
POST /enroll                              1. validate address → derive scriptPubKey
  { address, label, incoming_mode,        2. spk_hmac = HMAC(k_match, spk)
    channels[] }                          3. queue a baseline scan job → item PENDING
                                          4. label_ct = AEAD(k_store, label)
                                             dest_ct  = AEAD(k_store, channel dest)
                                             spk_ct   = AEAD(k_store, spk)  ← §4, reconciliation
                                          5. drop plaintext
                                          6. mint capability token (32 random bytes),
                                             store only sha256(token)
 ← { token, item_id, status: ARMING }     7. test-fire each channel; item ACTIVE only
                                             after the user confirms receipt
```

### Enrolment is asynchronous, and this is not optional

The baseline scan takes **~186 seconds**, measured. Three consequences:

1. **`ARMING` is a user-visible state.** The response returns immediately; the watch is not live
   until the scan completes. The UI must say so, and the user must be told when it arms.
2. **Scans serialise.** bitcoind runs one `scantxoutset` at a time. The job runner needs a
   depth-bounded queue and an answer for what a queued user sees. Ten signups in an hour is a
   half-hour tail on the last one.
3. **An abandoned scan does not stop.** Killing the client leaves the scan running on the node,
   consuming a core. The job runner must issue `scantxoutset abort` on its own death.

### Rules that make it genuinely forgetful

- The plaintext address exists only in request scope (invariant I1).
- The scan runs against our own node over localhost RPC with a whitelisted user. The address
  leaves the process only to reach our own node.
- No IP logging on the web tier. A Tor onion service is the flagship access path.
- The capability token is shown **once**. `sha256(token)` is the lookup key for everything.
  Lost token means lost service, stated plainly at signup.

---

## 3. Storage schema

```sql
CREATE TABLE watch (                      -- one anonymous tenant = one capability token
  id            INTEGER PRIMARY KEY,
  token_hash    BLOB NOT NULL UNIQUE,     -- sha256(capability token)
  balance_sats  INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'active',   -- active|grace|stopped
  alarm_undelivered INTEGER NOT NULL DEFAULT 0,   -- an alarm exhausted every channel
  created_at    INTEGER NOT NULL          -- day precision (invariant I3)
);

CREATE TABLE watch_item (
  id            INTEGER PRIMARY KEY,
  watch_id      INTEGER NOT NULL REFERENCES watch(id),
  chain         TEXT NOT NULL,
  spk_hmac      BLOB NOT NULL,            -- NOT unique: two tenants may watch one address
  spk_ct        BLOB NOT NULL,            -- AEAD(k_store, spk). Reconciliation rebuilds the
                                          -- descriptor from this; the HMAC above is one-way,
                                          -- so without it there is nothing to scan for (§4).
  label_ct      BLOB NOT NULL,
  incoming_mode TEXT NOT NULL DEFAULT 'info',     -- info|mute (outgoing is always alarm)
  status        TEXT NOT NULL DEFAULT 'arming',   -- arming|active|paused|stopped
  drip_rate     INTEGER NOT NULL DEFAULT 10,      -- sats/day
  created_at    INTEGER NOT NULL
);
CREATE INDEX idx_item_spk ON watch_item(spk_hmac);

CREATE TABLE utxo (                       -- CONFIRMED outpoints only; written by blocks alone
                                          -- (§4). Mempool-only coins live in memory and never
                                          -- reach this table: reconciliation compares it
                                          -- against scantxoutset, which cannot see them.
  item_id       INTEGER NOT NULL REFERENCES watch_item(id),
  outpoint_hmac BLOB NOT NULL,
  PRIMARY KEY (item_id, outpoint_hmac)
);
CREATE INDEX idx_utxo_op ON utxo(outpoint_hmac);

CREATE TABLE channel (
  id            INTEGER PRIMARY KEY,
  watch_id      INTEGER NOT NULL REFERENCES watch(id),
  kind          TEXT NOT NULL,            -- email|nostr|webhook|ntfy
  dest_ct       BLOB NOT NULL,
  privacy_ack   INTEGER NOT NULL DEFAULT 0,   -- user acknowledged a non-private channel
  verified_at   INTEGER                   -- test-fire confirmed; NULL means unusable
);

CREATE TABLE route (
  item_id       INTEGER NOT NULL REFERENCES watch_item(id),
  channel_id    INTEGER NOT NULL REFERENCES channel(id),
  min_severity  TEXT NOT NULL DEFAULT 'info',
  PRIMARY KEY (item_id, channel_id)
);

-- Deliberately NO event history (invariant I3). The outbox holds a row only while a
-- delivery is in flight; it is deleted on completion, success or permanent failure.
CREATE TABLE outbox (
  id            INTEGER PRIMARY KEY,
  item_id       INTEGER NOT NULL,
  channel_id    INTEGER NOT NULL,
  kind          TEXT NOT NULL,
  direction     TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  next_try_at   INTEGER NOT NULL
);
```

Run with `secure_delete=ON`; `VACUUM` after bulk deletion. SQLite leaves freed pages readable
otherwise, which quietly undoes a purge.

---

## 4. The matching loop

```
ZMQ rawtx / rawblock  (two separate SUB sockets — see below)
  → parse transaction
  → for each INPUT outpoint:  HMAC → lookup utxo       → OUTGOING (alarm)
  → for each OUTPUT spk:      HMAC → lookup watch_item → INCOMING (informational)
  → enqueue outbox rows → delivery workers
  → if this arrived in a BLOCK: apply it to the utxo set
       └─ spent outpoints deleted, new outputs to watched scripts inserted
```

Pure HMAC-and-compare. Plaintext chain data is public and is never persisted.

### The stream alerts; only confirmations write

**`rawtx` never mutates the stored UTXO set. `rawblock` does, and nothing else does.** A
mempool transaction produces the alert — that is the product, and the latency is the point —
but it leaves the record alone until it confirms.

This is not caution about unconfirmed transactions. It is what makes reconciliation *decidable*
at all. `scantxoutset` reads the chainstate, so it reports confirmed state and nothing else.
If the record were written on first sight, then every reconciliation pass would have to
distinguish two indistinguishable cases:

| We hold / node holds | If the record is confirmed-only | If the record is written on first sight |
|---|---|---|
| Node has it, we don't | We missed an INCOMING → insert | …or it is simply not confirmed yet |
| **We have it, node doesn't** | **We missed an OUTGOING → alarm** | …or we recorded an unconfirmed receipt |

The second row is the alarm — the one signal this service exists to produce. Under a
first-sight record, an unconfirmed *receipt* looks exactly like a missed *spend*, so
reconciliation would fire false alarms on the flagship path. And the reverse case is just as
bad: reconciling after an unconfirmed spend but before it confirms would read the still-unspent
coin as a missed incoming, **resurrect it into the record**, and then alarm a second time when
the spend confirms.

There is no way to check the disputed coin against the node's mempool, either. **We hold
outpoints only as HMACs, and an HMAC is one-way** — we cannot reconstruct a txid to ask
`gettxout` about. Reconciliation runs in exactly one direction: take the node's plaintext
unspents, HMAC them, diff. So the ambiguity cannot be resolved after the fact by asking; it has
to be excluded by construction, which is what a confirmed-only record does.

Storing "last seen at" per outpoint to quarantine recent ones is **not** an option: timestamps
at rest re-correlate the HMACs against public chain data, which is the exposure DESIGN §3b
exists to close.

Two consequences to implement, not to remember:

- **De-duplication is required.** The same transaction is seen twice — once in the mempool, once
  in a block — and must alert once. The seen-set is in memory only (see above: no timestamps at
  rest). After a restart, a transaction caught mid-confirmation may alert twice; a duplicate
  alert is a far cheaper failure than a missed one.
- **RBF and never-confirming transactions become free.** A replaced spend alerts (correctly — the
  coins were being moved) but never enters the record, so nothing has to be un-written.

### This loop must not assume it sees everything

See invariant I4. Three requirements:

1. **Two SUB sockets, one per endpoint.** A block message is ~1.7 MB and will crowd the
   transaction stream if they share a socket.
2. **Per-topic sequence tracking.** The 3rd ZMQ message part is a 4-byte little-endian counter.
   A discontinuity is a drop. Alert on it.
3. **Periodic reconciliation against the UTXO set**, repairing what the stream missed. This is a
   v1 requirement, not later hardening. Test it by *inducing* a gap — `tests/fixtures/with-gap.jsonl`
   exists for exactly this.

   Anchor the diff to a height. `scantxoutset` returns the `bestblock` it finished on, and it
   takes minutes, so the tip will often have moved on underneath it. Comparing a snapshot taken
   at height *h* against a record that has since advanced past *h* manufactures divergences that
   never existed on any chain — every block confirmed during the scan looks like a discrepancy.

   ⚠️ **The UTXO-set diff needs a schema change that is decided but not yet built.**
   `scantxoutset` takes descriptors; a descriptor contains the scriptPubKey; the schema stores
   `spk_hmac`, which is one-way. There is nothing to reconstruct a descriptor from, so the diff
   cannot be implemented until the script is recoverable.

   **Decided: an `spk_ct` column, `AEAD(k_store, spk)`.** The published claim is unaffected —
   the database alone stays unmatchable noise, because ciphertext without the key is noise. Nor
   does it meaningfully move the database-**plus**-master case, which §3b already classes as
   total: an attacker holding `k_match` can hash any candidate script and test it against the
   public UTXO set, so every watched script that holds coins is already recoverable with
   effort. This turns recoverable-with-effort into readable, under a compromise that was
   already conceded.

   Rejected: a whole-UTXO-set walk (`dumptxoutset`). It needs no plaintext at rest at all,
   which is genuinely stronger, but costs a multi-gigabyte dump plus HMACing ~166M outputs
   every pass — on a host chosen for being lean — and reconciles every tenant at once rather
   than per item.

4. **Chain catch-up**, which is what actually repairs the measured failure and needs neither of
   the above. Under the write rule a dropped `rawtx` costs alert *latency* and nothing else —
   the block that confirms it writes the record regardless. A dropped `rawblock` is what costs
   correctness, and it is repaired by noticing that the block in hand is not the child of the
   last one applied and fetching the difference by height. No descriptors, no scan, no plaintext.

   What it cannot do is survive a **reorg**: the record keeps no per-block provenance, so there
   is nothing to roll back, and it stops and says so rather than pretending. Closing that needs
   the UTXO-set diff above.

   ⚠️ **The read timeout must exceed the scan.** A short timeout cancels nothing; it abandons a
   scan that keeps running, so a conservatively short value *causes* the orphan it appears to
   prevent. 900 s for the scan call, 30 s for control calls.

The block handler additionally re-processes transactions for confirmation tracking and for
catch-up after downtime: on restart, rescan blocks since the last seen height.

> **Note:** the node is pruned. `getblock` below the prune height fails, so no design may assume
> arbitrary historical block retrieval.

---

## 5. Delivery channels

The privacy analysis is baked in as **types**, so the enrolment UI can rank channels honestly and
a renderer cannot over-share by accident.

```python
class PrivacyClass(Enum):
    E2E_PRIVATE      = "e2e"       # content + metadata private: Nostr NIP-17 gift-wrap
    ENDPOINT_TRUSTED = "endpoint"  # user controls the endpoint: webhook, self-hosted ntfy
    PROVIDER_READS   = "provider"  # operator reads content and metadata: email, ntfy.sh

@dataclass(frozen=True)
class Alert:
    kind: AlertKind                # movement | test_fire | low_balance | watch_stopped | heartbeat
    label: str                     # the user's own nickname — the ONLY user data in any alert
    chain: str
    direction: Direction | None    # outgoing (alarm) | incoming (informational)
    fired_at: datetime
    # No address. No amount. No txid. Renderers cannot leak what the dataclass does not carry.

class Channel(Protocol):
    kind: ClassVar[str]
    privacy_class: ClassVar[PrivacyClass]

    def validate_dest(self, raw: str) -> str: ...
    def send(self, dest: str, alert: Alert) -> DeliveryResult: ...
```

`Channel` is the main extension point and the cleanest unit of independent work — an
implementation can be built and tested with no node and no database.

| kind | class | notes |
|---|---|---|
| `email` | `PROVIDER_READS` | **First rail — reach.** Requires `privacy_ack`. Subject is a **constant** (subjects are logged and indexed everywhere); body is a minimal template. Enforce TLS, no opportunistic downgrade. ⚠️ See the hardening note below. |
| `nostr` | `E2E_PRIVATE` | NIP-17 gift-wrap to the user's npub — content *and* sender/recipient metadata sealed. The privacy-recommended default. ⚠️ See the relay-selection note below. |
| `webhook` | `ENDPOINT_TRUSTED` | POST JSON, HMAC-signed with a per-channel secret shown once so the user can authenticate us. Egress over Tor. |
| `ntfy` | either | Self-hosted URL is endpoint-trusted; the public instance is provider-reads — flag it. A random topic is not authentication. |

**Telegram is deliberately absent.** Bot chats are never end-to-end encrypted and the account is
phone-linked. It may be added later as `PROVIDER_READS` behind the same acknowledgement gate,
but that is a decision to make explicitly, not a default to drift into.

### Email carries work that lands outside the database

Postfix keeps its own plaintext copies — `mail.log` and the deferred queue both hold the
destination, bypassing `dest_ct` entirely. An email-capable release without log scrubbing and
queue purging **breaks the register-and-forget claim outside the database**, where the encryption
cannot help. That hardening ships with the email channel, not after it.

### Nostr publishes to our relay list, not the recipient's

`NostrChannel.send` stops at the first relay in `COLDWATCH_NOSTR_RELAYS` — one list, shared by
every destination — that acknowledges the event. NIP-17 properly resolves this by publishing the
gift wrap to every relay in the recipient's own `kind:10050` DM-relay list; that lookup is not
built. Until it is, an alarm can be accepted (`DeliveryResult(ok=True)`) by a relay the recipient's
client never reads from — a delivered receipt that isn't a delivery guarantee. See
[SECURITY.md](../SECURITY.md)'s accepted residuals.

### Delivery pipeline

```
match → outbox row per route → decrypt dest (in memory only)
      → render per-kind template → channel.send()
      → retry with exponential backoff (retriable failures only)
      → SUCCESS: delete the outbox row
      → EXHAUSTED on an alarm: set watch.alarm_undelivered, bump a label-free
        escalation metric visible to the watchdog, delete the row anyway
```

**Send-timing correlation.** An observer who sees a message arrive N seconds after a public
on-chain transaction can link identity to address without reading any content. Outgoing alarms
send **instantly** — speed is the product — so this residual is accepted and stated publicly.
Informational, heartbeat and balance messages get random jitter of minutes, and heartbeats
double as cover traffic.

This is why the honest claim is **unlinkability**, never "nobody can tell."

---

## 6. Retention

Publish this table; it is a trust asset.

| Data | Retention |
|---|---|
| Watched targets | HMAC only, until the user deletes them |
| Labels, channel destinations | AEAD-encrypted, until deleted |
| Alert history | **Never stored** |
| Outbox rows | Only while a delivery is in flight |
| Web logs | No IP logging |
| Timestamps | Day precision |
| Stopped tenants | Purged |

A token-authenticated nuke endpoint deletes everything for a tenant immediately.

---

## 7. Build order

1. **Ingest core** — two SUB sockets, sequence-gap detection, reconciliation, scan supervisor
   with abort-on-death. *The risk lives here.* — **built, except the UTXO-set diff**
2. **Channel abstraction** + the Nostr implementation (proves the delivery pipeline cheaply).
   — contract built; Nostr (NIP-17 gift wrap) built
   ([#3](https://github.com/Wired4ncer/coldwatch/issues/3))
3. **Email channel** + postfix hardening (the reach rail, and the harder one).
   — email channel built ([#2](https://github.com/Wired4ncer/coldwatch/issues/2)); postfix
   hardening and the mail log/queue purge still open
   ([#22](https://github.com/Wired4ncer/coldwatch/issues/22))
4. **Enrolment API** + capability tokens + the arming state machine.
   — open ([#23](https://github.com/Wired4ncer/coldwatch/issues/23))
5. **Payment** — Lightning, prepaid balance, drip debit.
6. **Watchdog** on separate infrastructure, plus the public uptime page.

### Where the ingest core actually stands

| Piece | State |
|---|---|
| Sequence-gap detection, transaction parsing, HMAC matching | built |
| Confirmed-only write rule (§4) | built |
| Block parsing, mempool/confirmation de-duplication | built |
| Chain catch-up — refetch blocks the stream dropped | built |
| Two live SUB sockets | built |
| Scan supervisor — queue, batching, abort-on-death | built (mechanism only) |
| **UTXO-set diff and reorg repair** | **blocked on enrolment writing `spk_ct`** ([#21](https://github.com/Wired4ncer/coldwatch/issues/21)) |
| `ARMING` state, test-fire ordering | with the enrolment API |

Chain catch-up is **proven against the production node**, not only against fixtures
([#24](https://github.com/Wired4ncer/coldwatch/issues/24)): a six-block gap was induced, the
follower refetched exactly the missed blocks, and a deposit and its spend — both in blocks the
subscriber never received — produced INCOMING and then OUTGOING. Reproduce with
`tools/induced_gap_proof.py`.

What is still **not** proven live, and should not be claimed:

- **Reorg handling.** Detected and refused rather than repaired, and a reorg cannot be induced
  to order. Closing it needs the UTXO-set diff ([#21](https://github.com/Wired4ncer/coldwatch/issues/21)).
- **Drop behaviour under load.** The sockets have been watched live without a single dropped
  message, which says nothing about a period that does drop them
  ([#25](https://github.com/Wired4ncer/coldwatch/issues/25)).
- **The RPC whitelist, dynamically.** The proof authenticated with the node's cookie, which
  bypasses `rpcwhitelist`. Compatibility was checked statically instead — every method the code
  calls appears in the configured line — which is sound for a per-method list but is inspection,
  not a live run.

---

## 8. What the node must provide

Everything here is read-only. The service never sends a transaction, never touches a wallet, and
never asks the node to do anything that changes state.

### ZMQ

```
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
```

Two endpoints, subscribed on **two separate sockets** — see §4. The high-water mark on both
sides is worth setting deliberately: the default of 1000 is the setting under which ~832
transactions were measured lost across 3 gaps in 40 minutes. Raising it reduces loss and cannot
eliminate it, which is why reconciliation exists rather than being an optimisation.

### RPC

Exactly four methods, and the whitelist should grant no more:

| Method | Used for |
|---|---|
| `scantxoutset` | the enrolment baseline, and later the UTXO-set diff |
| `getblockhash` | finding a block by height during catch-up |
| `getblock` | fetching a dropped block (verbosity 0) and reading a height (verbosity 1) |
| `getblockchaininfo` / `getblockcount` | liveness and tip checks |

⚠️ **`getblockheader` is deliberately not used**, even though it is the natural call for reading
a height and a confirmation count. `getblock` at verbosity 1 returns both, and keeping the
whitelist one method narrower is worth more than the extra bytes: the whitelist is the
difference between a compromised service being able to *read* the chain and being able to *act*
on the node. This was found the expensive way — the obvious implementation passed every test
against a fake and would have failed on first contact with a whitelisted node.

Under `rpcwhitelistdefault=0` a whitelist that omits a method the code calls produces a failure
that no offline test can predict. **Check the code's calls against the deployed whitelist when
either changes.**

### Pruning

A pruned node is sufficient and archival buys nothing — there is no `txindex`, no history read,
and no arbitrary txid lookup anywhere in the design. The one real constraint: **the prune target
is the catch-up window.** Blocks below the prune height cannot be refetched, so a service down
longer than that window cannot repair itself from blocks and fails loudly rather than pretending.
At a 50 GiB target that window measured ~29,000 blocks, roughly 200 days.
