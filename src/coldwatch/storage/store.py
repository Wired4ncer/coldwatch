"""The database, and the only code that holds `k_store`.

Everything a caller can get back out of here is either a keyed hash, an integer id, a status,
or a plaintext that this module decrypted *for that call* -- a label for a render, a
destination for a send, a script for a reconciliation descriptor. The caller uses it and drops
it; nothing here retains it, logs it or puts it in an exception.

What is never in the file, by construction rather than by care:

* the capability token -- only `sha256(token)` is written, and the token is returned to the
  caller exactly once, from `create_watch`;
* a scriptPubKey, label or destination in the clear -- each is `AEAD(k_store, ·)` with the
  column's purpose and the tenant's id as associated data, so a ciphertext cannot be read as
  another column or moved to another tenant;
* a timestamp finer than a day (invariant I3);
* a row that outlives its purpose: `secure_delete=ON` so a deleted row is overwritten, and
  `purge_watch` runs `VACUUM` afterwards so freed pages are not left readable.

The `WatchIndex` half (`items_watching_spk` and the three others) is what the matching loop
calls thousands of times a second, and it consults only `spk_hmac`, `outpoint_hmac` and
`status`. `k_store` is not touched on that path -- the split docs/architecture.md §1 asks for.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import struct
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Self

from coldwatch.crypto import open_, seal
from coldwatch.match.keys import Subkeys, spk_hmac

from .schema import SCHEMA, SCHEMA_VERSION

__all__ = [
    "TOKEN_BYTES",
    "ChannelRow",
    "Item",
    "ItemStatus",
    "NotActivatable",
    "NotArmable",
    "Store",
    "UnknownRow",
    "Watch",
    "WatchStatus",
]

#: Capability token size. 256 bits: no recovery path exists, so it has to be unguessable
#: forever rather than merely for a session.
TOKEN_BYTES = 32

#: Associated-data purposes. A `dest_ct` presented as an `spk_ct` fails to open.
_AAD_SPK = b"spk"
_AAD_LABEL = b"label"
_AAD_DEST = b"dest"


class ItemStatus(Enum):
    ARMING = "arming"
    """Baseline scan queued or running. Not tracked, not alertable."""
    ARMED = "armed"
    """Baseline written; awaiting test-fire confirmation. Tracked, not alertable."""
    ACTIVE = "active"
    """Tracked and alertable."""
    PAUSED = "paused"
    """Tracked -- blocks still write the record -- but nothing is sent."""
    STOPPED = "stopped"
    """Neither. Kept only until the tenant purge."""


#: Items whose outpoint set the block path keeps current. `arming` has no set yet; `stopped`
#: has no future. Whether a *match* on one of these becomes an alert is the delivery layer's
#: decision, keyed on the same status -- this index answers only "is the record live".
_TRACKED = tuple(s.value for s in (ItemStatus.ARMED, ItemStatus.ACTIVE, ItemStatus.PAUSED))


class WatchStatus(Enum):
    ACTIVE = "active"
    GRACE = "grace"
    STOPPED = "stopped"


class UnknownRow(LookupError):
    """No such watch, item or channel. Carries the id and nothing else."""


class NotArmable(RuntimeError):
    """`arm` on an item that is not `arming` -- a second baseline would overwrite a record
    that blocks have been keeping current since the first."""


class NotActivatable(RuntimeError):
    """`activate` on an item that is not `armed`, or whose routes have no verified channel.

    An item with no proven channel is a watch that fails at the one moment it matters
    (invariant I5), so the store refuses rather than trusting the caller to have checked.
    """


@dataclass(frozen=True)
class Watch:
    id: int
    status: WatchStatus
    balance_sats: int
    alarm_undelivered: bool


@dataclass(frozen=True)
class Item:
    id: int
    watch_id: int
    chain: str
    status: ItemStatus
    incoming_mode: str
    drip_rate: int


@dataclass(frozen=True)
class ChannelRow:
    """A channel as the delivery layer sees it: no destination. That is fetched separately,
    just in time, by `channel_dest`."""

    id: int
    kind: str
    privacy_ack: bool
    verified: bool
    min_severity: str


def _today() -> int:
    """Days since the epoch. The only clock resolution that may reach the file."""
    return int(time.time() // 86400)


def _aad(purpose: bytes, watch_id: int) -> bytes:
    return purpose + struct.pack("<Q", watch_id)


class Store:
    """One SQLite database. Safe to share between the matching thread and an API thread."""

    def __init__(self, path: str, keys: Subkeys, *, today: Callable[[], int] = _today) -> None:
        self._keys = keys
        self._today = today
        self._lock = threading.RLock()
        # `check_same_thread=False` because the loop and the API are different threads; the
        # lock above is what makes that safe, not SQLite's own serialised mode.
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level="DEFERRED")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        with self._db:
            self._db.executescript(SCHEMA)
            self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ── tenants ─────────────────────────────────────────────────────────────────────────────

    def create_watch(self) -> tuple[bytes, int]:
        """Mint a tenant. Returns the capability token -- the only time it is ever available
        -- and the watch id."""
        token = secrets.token_bytes(TOKEN_BYTES)
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO watch (token_hash, created_at) VALUES (?, ?)",
                (hashlib.sha256(token).digest(), self._today()),
            )
        return token, cur.lastrowid

    def watch_by_token(self, token: bytes) -> Watch | None:
        """The lookup every authenticated request starts with. `None` for an unknown token;
        the caller decides what an unauthenticated response looks like."""
        with self._lock:
            row = self._db.execute(
                "SELECT id, status, balance_sats, alarm_undelivered FROM watch"
                " WHERE token_hash = ?",
                (hashlib.sha256(token).digest(),),
            ).fetchone()
        if row is None:
            return None
        return Watch(row[0], WatchStatus(row[1]), row[2], bool(row[3]))

    def watch(self, watch_id: int) -> Watch:
        with self._lock:
            row = self._db.execute(
                "SELECT id, status, balance_sats, alarm_undelivered FROM watch WHERE id = ?",
                (watch_id,),
            ).fetchone()
        if row is None:
            raise UnknownRow(watch_id)
        return Watch(row[0], WatchStatus(row[1]), row[2], bool(row[3]))

    def purge_watch(self, watch_id: int) -> None:
        """Remove a tenant and everything under it, and give the freed pages back overwritten.

        `ON DELETE CASCADE` takes items, outpoints, channels, routes and outbox rows with the
        watch; `secure_delete` zeroes each as it goes; `VACUUM` rebuilds the file so nothing
        of them remains in a free page. `VACUUM` cannot run inside a transaction, hence the
        commit between.
        """
        with self._lock:
            with self._db:
                cur = self._db.execute("DELETE FROM watch WHERE id = ?", (watch_id,))
                if cur.rowcount == 0:
                    raise UnknownRow(watch_id)
            self._db.execute("VACUUM")

    # ── items ───────────────────────────────────────────────────────────────────────────────

    def add_item(
        self,
        watch_id: int,
        chain: str,
        spk: bytes,
        label: str,
        *,
        incoming_mode: str = "info",
    ) -> int:
        """Enrol a scriptPubKey. The item starts `arming`; `arm` moves it on.

        `spk` is plaintext here, in request scope only (invariant I1): it leaves this call as
        a keyed hash and a ciphertext, and the caller must not keep it either.
        """
        with self._lock, self._db:
            self._require_watch(watch_id)
            cur = self._db.execute(
                "INSERT INTO watch_item"
                " (watch_id, chain, spk_hmac, spk_ct, label_ct, incoming_mode, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    watch_id,
                    chain,
                    spk_hmac(self._keys.match, spk),
                    seal(self._keys.store, spk, _aad(_AAD_SPK, watch_id)),
                    seal(self._keys.store, label.encode(), _aad(_AAD_LABEL, watch_id)),
                    incoming_mode,
                    self._today(),
                ),
            )
        return cur.lastrowid

    def item(self, item_id: int) -> Item:
        with self._lock:
            row = self._db.execute(
                "SELECT id, watch_id, chain, status, incoming_mode, drip_rate"
                " FROM watch_item WHERE id = ?",
                (item_id,),
            ).fetchone()
        if row is None:
            raise UnknownRow(item_id)
        return Item(row[0], row[1], row[2], ItemStatus(row[3]), row[4], row[5])

    def items_of(self, watch_id: int) -> tuple[Item, ...]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, watch_id, chain, status, incoming_mode, drip_rate"
                " FROM watch_item WHERE watch_id = ? ORDER BY id",
                (watch_id,),
            ).fetchall()
        return tuple(Item(r[0], r[1], r[2], ItemStatus(r[3]), r[4], r[5]) for r in rows)

    def item_spk(self, item_id: int) -> bytes:
        """Decrypt the scriptPubKey -- for building a `scantxoutset` descriptor and nothing
        else. This is the column issue #21 exists to have."""
        with self._lock:
            row = self._db.execute(
                "SELECT watch_id, spk_ct FROM watch_item WHERE id = ?", (item_id,)
            ).fetchone()
        if row is None:
            raise UnknownRow(item_id)
        return open_(self._keys.store, row[1], _aad(_AAD_SPK, row[0]))

    def item_label(self, item_id: int) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT watch_id, label_ct FROM watch_item WHERE id = ?", (item_id,)
            ).fetchone()
        if row is None:
            raise UnknownRow(item_id)
        return open_(self._keys.store, row[1], _aad(_AAD_LABEL, row[0])).decode()

    def arm(self, item_id: int, outpoint_hmacs: Sequence[bytes]) -> None:
        """Write the baseline the scan found and move the item `arming` → `armed`.

        Atomic with the status change, so a crash between the two cannot leave an `arming`
        item with half a baseline that a retry would then double. Refuses on any other status:
        once `armed`, blocks own the record and a second baseline would be older than it.

        ⚠️ The baseline is a snapshot at the height the scan finished on, and the tip has
        usually moved during the ~186 s it takes. Closing that window -- replaying the blocks
        between the scan's `bestblock` and the tip through `Matcher.apply` -- is the enrolment
        service's job, before it calls this. Recording the height here would put a
        block-precision timestamp at rest, and the service can hold it in memory for the
        minute it matters.
        """
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE watch_item SET status = ? WHERE id = ? AND status = ?",
                (ItemStatus.ARMED.value, item_id, ItemStatus.ARMING.value),
            )
            if cur.rowcount == 0:
                self._require_item(item_id)
                raise NotArmable(item_id)
            self._db.executemany(
                "INSERT OR IGNORE INTO utxo (item_id, outpoint_hmac) VALUES (?, ?)",
                ((item_id, h) for h in outpoint_hmacs),
            )

    def activate(self, item_id: int) -> None:
        """`armed` → `active`, only once a routed channel has a confirmed test-fire."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT status,"
                " EXISTS (SELECT 1 FROM route r JOIN channel c ON c.id = r.channel_id"
                "         WHERE r.item_id = watch_item.id AND c.verified_at IS NOT NULL)"
                " FROM watch_item WHERE id = ?",
                (item_id,),
            ).fetchone()
            if row is None:
                raise UnknownRow(item_id)
            if row[0] != ItemStatus.ARMED.value or not row[1]:
                raise NotActivatable(item_id)
            self._db.execute(
                "UPDATE watch_item SET status = ? WHERE id = ?",
                (ItemStatus.ACTIVE.value, item_id),
            )

    def pause(self, item_id: int) -> None:
        self._transition(item_id, ItemStatus.ACTIVE, ItemStatus.PAUSED)

    def resume(self, item_id: int) -> None:
        self._transition(item_id, ItemStatus.PAUSED, ItemStatus.ACTIVE)

    def stop_item(self, item_id: int) -> None:
        """Any state → `stopped`, dropping the outpoint set: a stopped item's record is a list
        of coins nobody asked us to keep."""
        with self._lock, self._db:
            self._require_item(item_id)
            self._db.execute("DELETE FROM utxo WHERE item_id = ?", (item_id,))
            self._db.execute(
                "UPDATE watch_item SET status = ? WHERE id = ?",
                (ItemStatus.STOPPED.value, item_id),
            )

    def _transition(self, item_id: int, from_: ItemStatus, to: ItemStatus) -> None:
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE watch_item SET status = ? WHERE id = ? AND status = ?",
                (to.value, item_id, from_.value),
            )
            if cur.rowcount == 0:
                self._require_item(item_id)
                raise NotActivatable(item_id)

    # ── channels and routes ─────────────────────────────────────────────────────────────────

    def add_channel(self, watch_id: int, kind: str, dest: str, *, privacy_ack: bool = False) -> int:
        """Store a destination the channel has already validated (`Channel.validate_dest`).
        Unverified until `mark_verified`; `activate` will not count it before then."""
        with self._lock, self._db:
            self._require_watch(watch_id)
            cur = self._db.execute(
                "INSERT INTO channel (watch_id, kind, dest_ct, privacy_ack) VALUES (?, ?, ?, ?)",
                (
                    watch_id,
                    kind,
                    seal(self._keys.store, dest.encode(), _aad(_AAD_DEST, watch_id)),
                    int(privacy_ack),
                ),
            )
        return cur.lastrowid

    def channel_dest(self, channel_id: int) -> str:
        """Decrypt a destination for one send. Use it, then let it go."""
        with self._lock:
            row = self._db.execute(
                "SELECT watch_id, dest_ct FROM channel WHERE id = ?", (channel_id,)
            ).fetchone()
        if row is None:
            raise UnknownRow(channel_id)
        return open_(self._keys.store, row[1], _aad(_AAD_DEST, row[0])).decode()

    def mark_verified(self, channel_id: int) -> None:
        """The user confirmed the test-fire arrived. Day precision, like every timestamp."""
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE channel SET verified_at = ? WHERE id = ?", (self._today(), channel_id)
            )
            if cur.rowcount == 0:
                raise UnknownRow(channel_id)

    def route(self, item_id: int, channel_id: int, *, min_severity: str = "info") -> None:
        """Send this item's alerts to this channel. Both must belong to the same tenant."""
        with self._lock, self._db:
            owner = self._db.execute(
                "SELECT i.watch_id = c.watch_id FROM watch_item i, channel c"
                " WHERE i.id = ? AND c.id = ?",
                (item_id, channel_id),
            ).fetchone()
            if owner is None:
                raise UnknownRow((item_id, channel_id))
            if not owner[0]:
                raise ValueError("item and channel belong to different watches")
            self._db.execute(
                "INSERT OR REPLACE INTO route (item_id, channel_id, min_severity)"
                " VALUES (?, ?, ?)",
                (item_id, channel_id, min_severity),
            )

    def channels_for(self, item_id: int) -> tuple[ChannelRow, ...]:
        """The routed channels of an item, without their destinations."""
        with self._lock:
            rows = self._db.execute(
                "SELECT c.id, c.kind, c.privacy_ack, c.verified_at IS NOT NULL, r.min_severity"
                " FROM route r JOIN channel c ON c.id = r.channel_id"
                " WHERE r.item_id = ? ORDER BY c.id",
                (item_id,),
            ).fetchall()
        return tuple(ChannelRow(r[0], r[1], bool(r[2]), bool(r[3]), r[4]) for r in rows)

    # ── WatchIndex: what the matching loop sees ─────────────────────────────────────────────

    def items_watching_spk(self, spk_hmac_: bytes) -> Sequence[int]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT id FROM watch_item WHERE spk_hmac = ? AND status IN "
                f"({','.join('?' * len(_TRACKED))}) ORDER BY id",
                (spk_hmac_, *_TRACKED),
            ).fetchall()
        return tuple(r[0] for r in rows)

    def items_owning_outpoint(self, outpoint_hmac_: bytes) -> Sequence[int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT item_id FROM utxo WHERE outpoint_hmac = ? ORDER BY item_id",
                (outpoint_hmac_,),
            ).fetchall()
        return tuple(r[0] for r in rows)

    def add_outpoint(self, item_id: int, outpoint_hmac_: bytes) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO utxo (item_id, outpoint_hmac) VALUES (?, ?)",
                (item_id, outpoint_hmac_),
            )

    def drop_outpoint(self, item_id: int, outpoint_hmac_: bytes) -> None:
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM utxo WHERE item_id = ? AND outpoint_hmac = ?",
                (item_id, outpoint_hmac_),
            )

    def outpoint_count(self, item_id: int) -> int:
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) FROM utxo WHERE item_id = ?", (item_id,)
            ).fetchone()[0]

    # ── helpers ─────────────────────────────────────────────────────────────────────────────

    def _require_watch(self, watch_id: int) -> None:
        if self._db.execute("SELECT 1 FROM watch WHERE id = ?", (watch_id,)).fetchone() is None:
            raise UnknownRow(watch_id)

    def _require_item(self, item_id: int) -> None:
        if self._db.execute("SELECT 1 FROM watch_item WHERE id = ?", (item_id,)).fetchone() is None:
            raise UnknownRow(item_id)
