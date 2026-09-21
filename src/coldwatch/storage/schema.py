"""The schema from docs/architecture.md §3, verbatim where it can be.

One deliberate addition: `watch_item.status` has an **`armed`** state between `arming` and
`active`. The baseline scan finishing and the user confirming the test-fire are two events
minutes to days apart, and the record must be kept current during that gap -- a coin spent
after the baseline but before confirmation is still a spend the loop has to fold in, or the
row goes stale and the first reconciliation pass raises a false alarm. So an `armed` item is
tracked (blocks write its outpoints) but not yet alertable; `active` is both.
"""

from __future__ import annotations

__all__ = ["SCHEMA", "SCHEMA_VERSION"]

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS watch (
  id            INTEGER PRIMARY KEY,
  token_hash    BLOB NOT NULL UNIQUE,
  balance_sats  INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'grace', 'stopped')),
  alarm_undelivered INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS watch_item (
  id            INTEGER PRIMARY KEY,
  watch_id      INTEGER NOT NULL REFERENCES watch(id) ON DELETE CASCADE,
  chain         TEXT NOT NULL,
  spk_hmac      BLOB NOT NULL,
  spk_ct        BLOB NOT NULL,
  label_ct      BLOB NOT NULL,
  incoming_mode TEXT NOT NULL DEFAULT 'info'
                CHECK (incoming_mode IN ('info', 'mute')),
  status        TEXT NOT NULL DEFAULT 'arming'
                CHECK (status IN ('arming', 'armed', 'active', 'paused', 'stopped')),
  drip_rate     INTEGER NOT NULL DEFAULT 10,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_item_spk ON watch_item(spk_hmac);

CREATE TABLE IF NOT EXISTS utxo (
  item_id       INTEGER NOT NULL REFERENCES watch_item(id) ON DELETE CASCADE,
  outpoint_hmac BLOB NOT NULL,
  PRIMARY KEY (item_id, outpoint_hmac)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_utxo_op ON utxo(outpoint_hmac);

CREATE TABLE IF NOT EXISTS channel (
  id            INTEGER PRIMARY KEY,
  watch_id      INTEGER NOT NULL REFERENCES watch(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  dest_ct       BLOB NOT NULL,
  privacy_ack   INTEGER NOT NULL DEFAULT 0,
  verified_at   INTEGER
);

CREATE TABLE IF NOT EXISTS route (
  item_id       INTEGER NOT NULL REFERENCES watch_item(id) ON DELETE CASCADE,
  channel_id    INTEGER NOT NULL REFERENCES channel(id) ON DELETE CASCADE,
  min_severity  TEXT NOT NULL DEFAULT 'info'
                CHECK (min_severity IN ('info', 'alarm')),
  PRIMARY KEY (item_id, channel_id)
) WITHOUT ROWID;

-- Deliberately NO event history (invariant I3). A row lives here only while a delivery is
-- in flight and is deleted on completion, success or permanent failure.
CREATE TABLE IF NOT EXISTS outbox (
  id            INTEGER PRIMARY KEY,
  item_id       INTEGER NOT NULL REFERENCES watch_item(id) ON DELETE CASCADE,
  channel_id    INTEGER NOT NULL REFERENCES channel(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  direction     TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  next_try_at   INTEGER NOT NULL
);
"""
