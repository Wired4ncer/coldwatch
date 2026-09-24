"""The store: what goes in, what can come back out, and what is provably not in the file.

The tests that matter most read the database file's raw bytes. "The column is encrypted" is
a claim about code; "the script's bytes are not in the file" is a measurement.
"""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from coldwatch.channels import Direction
from coldwatch.crypto import AuthenticationFailed
from coldwatch.match import Match, Matcher, parse_tx, spk_hmac
from coldwatch.match.keys import derive_subkeys, outpoint_hmac
from coldwatch.storage import (
    TOKEN_BYTES,
    BadTransition,
    ItemStatus,
    NotActivatable,
    NotArmable,
    PurgeIncomplete,
    Store,
    UnknownRow,
    WatchStatus,
)
from support import PREV, build_tx, dsha256, spk

MASTER = b"store-test-master-secret-32-bytes!"
COLD = spk(0xC0)
LABEL = "grandmother's cold card"
DEST = "someone@example.invalid"
TODAY = 20_700


@pytest.fixture
def keys():
    return derive_subkeys(MASTER)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "coldwatch.sqlite")


@pytest.fixture
def store(db_path, keys):
    with Store(db_path, keys, today=lambda: TODAY) as s:
        yield s


def file_bytes(path: str) -> bytes:
    """Everything SQLite wrote, WAL included, after the connection is gone."""
    data = b""
    for suffix in ("", "-wal", "-journal"):
        try:
            with open(path + suffix, "rb") as f:
                data += f.read()
        except FileNotFoundError:
            pass
    return data


def enrolled(store: Store):
    """A tenant with one item and one routed, unverified channel."""
    token, watch_id = store.create_watch()
    item_id = store.add_item(watch_id, "btc", COLD, LABEL)
    channel_id = store.add_channel(watch_id, "email", DEST, privacy_ack=True)
    store.route(item_id, channel_id)
    return token, watch_id, item_id, channel_id


# ── tokens ──────────────────────────────────────────────────────────────────────────────────


def test_token_is_returned_once_and_looks_up_the_watch(store):
    token, watch_id = store.create_watch()
    assert len(token) == TOKEN_BYTES
    found = store.watch_by_token(token)
    assert found is not None and found.id == watch_id
    assert found.status is WatchStatus.ACTIVE


def test_unknown_token_is_none_not_an_exception(store):
    assert store.watch_by_token(bytes(TOKEN_BYTES)) is None


def test_two_watches_get_different_tokens(store):
    a, _ = store.create_watch()
    b, _ = store.create_watch()
    assert a != b


def test_only_the_token_hash_is_stored(db_path, keys):
    with Store(db_path, keys) as store:
        token, _ = store.create_watch()
    data = file_bytes(db_path)
    assert token not in data
    assert hashlib.sha256(token).digest() in data


# ── nothing in the clear ────────────────────────────────────────────────────────────────────


def test_script_label_and_destination_are_not_in_the_file(db_path, keys):
    with Store(db_path, keys) as store:
        enrolled(store)
    data = file_bytes(db_path)
    assert COLD not in data
    assert LABEL.encode() not in data
    assert DEST.encode() not in data
    # ...and the keyed hash is, which is what the loop matches on.
    assert spk_hmac(keys.match, COLD) in data


def test_plaintexts_come_back_only_through_the_key(store, keys):
    _, _, item_id, channel_id = enrolled(store)
    assert store.item_spk(item_id) == COLD
    assert store.item_label(item_id) == LABEL
    assert store.channel_dest(channel_id) == DEST


def test_ciphertext_is_bound_to_its_column(store, keys):
    """A `dest_ct` planted in `spk_ct` must not open as a script."""
    _, _, item_id, channel_id = enrolled(store)
    dest_ct = store._db.execute("SELECT dest_ct FROM channel WHERE id = ?", (channel_id,)).fetchone()[0]
    with store._db:
        store._db.execute("UPDATE watch_item SET spk_ct = ? WHERE id = ?", (dest_ct, item_id))
    with pytest.raises(AuthenticationFailed):
        store.item_spk(item_id)


def test_ciphertext_is_bound_to_its_tenant(store, keys):
    """The same column moved between two watches must not open either."""
    _, _, item_a, _ = enrolled(store)
    _, _, item_b, _ = enrolled(store)
    ct_a = store._db.execute("SELECT spk_ct FROM watch_item WHERE id = ?", (item_a,)).fetchone()[0]
    with store._db:
        store._db.execute("UPDATE watch_item SET spk_ct = ? WHERE id = ?", (ct_a, item_b))
    with pytest.raises(AuthenticationFailed):
        store.item_spk(item_b)


def test_a_tampered_label_is_refused_not_rendered(store):
    _, _, item_id, _ = enrolled(store)
    ct = bytearray(
        store._db.execute("SELECT label_ct FROM watch_item WHERE id = ?", (item_id,)).fetchone()[0]
    )
    ct[20] ^= 0x01
    with store._db:
        store._db.execute("UPDATE watch_item SET label_ct = ? WHERE id = ?", (bytes(ct), item_id))
    with pytest.raises(AuthenticationFailed):
        store.item_label(item_id)


def test_secure_delete_is_on(store):
    assert store._db.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_timestamps_are_day_precision(store):
    _, watch_id, item_id, channel_id = enrolled(store)
    store.mark_verified(channel_id)
    rows = store._db.execute(
        "SELECT (SELECT created_at FROM watch WHERE id = ?),"
        " (SELECT created_at FROM watch_item WHERE id = ?),"
        " (SELECT verified_at FROM channel WHERE id = ?)",
        (watch_id, item_id, channel_id),
    ).fetchone()
    assert rows == (TODAY, TODAY, TODAY)


def test_there_is_no_event_table(store):
    names = {
        r[0] for r in store._db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    # `sqlite_sequence` is SQLite's own, created by AUTOINCREMENT: one row per table holding
    # the highest id ever issued. A counter, not a history -- no times, no per-row trace.
    assert names == {
        "watch", "watch_item", "utxo", "channel", "route", "outbox", "sqlite_sequence",
    }
    assert {r[1] for r in store._db.execute("PRAGMA table_info(sqlite_sequence)")} == {
        "name", "seq",
    }


# ── the item state machine ──────────────────────────────────────────────────────────────────


def test_a_new_item_is_arming_and_invisible_to_the_loop(store, keys):
    _, _, item_id, _ = enrolled(store)
    assert store.item(item_id).status is ItemStatus.ARMING
    assert store.items_watching_spk(spk_hmac(keys.match, COLD)) == ()


def test_arm_writes_the_baseline_and_makes_the_item_tracked(store, keys):
    _, _, item_id, _ = enrolled(store)
    coin = outpoint_hmac(keys.match, PREV, 3)
    store.arm(item_id, [coin, coin])
    assert store.item(item_id).status is ItemStatus.ARMED
    assert store.items_owning_outpoint(coin) == (item_id,)
    assert store.outpoint_count(item_id) == 1
    assert store.items_watching_spk(spk_hmac(keys.match, COLD)) == (item_id,)


def test_arm_twice_is_refused(store, keys):
    _, _, item_id, _ = enrolled(store)
    store.arm(item_id, [])
    with pytest.raises(NotArmable):
        store.arm(item_id, [outpoint_hmac(keys.match, PREV, 0)])


def test_arm_unknown_item_is_unknown(store):
    with pytest.raises(UnknownRow):
        store.arm(999, [])


def test_activate_needs_an_armed_item_with_a_verified_channel(store):
    _, _, item_id, channel_id = enrolled(store)
    with pytest.raises(NotActivatable):
        store.activate(item_id)  # still arming
    store.arm(item_id, [])
    with pytest.raises(NotActivatable):
        store.activate(item_id)  # armed, but no channel has been proven
    store.mark_verified(channel_id)
    store.activate(item_id)
    assert store.item(item_id).status is ItemStatus.ACTIVE


def test_a_verified_channel_that_is_not_routed_does_not_count(store):
    _, watch_id, item_id, _ = enrolled(store)
    other = store.add_channel(watch_id, "nostr", "npub1other")
    store.mark_verified(other)
    store.arm(item_id, [])
    with pytest.raises(NotActivatable):
        store.activate(item_id)


def test_pause_keeps_the_record_live_and_resume_restores(store, keys):
    _, _, item_id, channel_id = enrolled(store)
    store.arm(item_id, [])
    store.mark_verified(channel_id)
    store.activate(item_id)
    store.pause(item_id)
    assert store.item(item_id).status is ItemStatus.PAUSED
    # Blocks must still write a paused item, or its record rots while nobody is looking.
    assert store.items_watching_spk(spk_hmac(keys.match, COLD)) == (item_id,)
    store.resume(item_id)
    assert store.item(item_id).status is ItemStatus.ACTIVE


def test_pause_from_the_wrong_state_is_refused(store):
    _, _, item_id, _ = enrolled(store)
    with pytest.raises(BadTransition):
        store.pause(item_id)


def test_stop_drops_the_coins_and_leaves_the_loop(store, keys):
    _, _, item_id, _ = enrolled(store)
    coin = outpoint_hmac(keys.match, PREV, 0)
    store.arm(item_id, [coin])
    store.stop_item(item_id)
    assert store.item(item_id).status is ItemStatus.STOPPED
    assert store.items_owning_outpoint(coin) == ()
    assert store.items_watching_spk(spk_hmac(keys.match, COLD)) == ()


# ── routes and channels ─────────────────────────────────────────────────────────────────────


def test_route_across_tenants_is_refused(store):
    _, _, item_a, _ = enrolled(store)
    _, _, _, channel_b = enrolled(store)
    with pytest.raises(ValueError):
        store.route(item_a, channel_b)


def test_channels_for_carries_no_destination(store):
    _, _, item_id, channel_id = enrolled(store)
    (row,) = store.channels_for(item_id)
    assert row.id == channel_id and row.kind == "email"
    assert row.privacy_ack and not row.verified
    assert DEST not in repr(row)
    store.mark_verified(channel_id)
    assert store.channels_for(item_id)[0].verified


def test_add_item_on_unknown_watch_is_unknown(store):
    with pytest.raises(UnknownRow):
        store.add_item(42, "btc", COLD, LABEL)


# ── the loop runs on the store ──────────────────────────────────────────────────────────────


def test_the_real_matcher_runs_on_the_store(store, keys):
    _, _, item_id, _ = enrolled(store)
    store.arm(item_id, [])
    matcher = Matcher(keys.match, store)

    deposit = build_tx([(PREV, 0)], [COLD])
    assert matcher.process(parse_tx(deposit)) == (Match(item_id, Direction.INCOMING),)
    assert store.outpoint_count(item_id) == 1

    spend = build_tx([(dsha256(deposit), 0)], [spk(0x11)])
    assert matcher.process(parse_tx(spend)) == (Match(item_id, Direction.OUTGOING),)
    assert store.outpoint_count(item_id) == 0


def test_two_tenants_watching_one_script_both_match(store, keys):
    _, _, item_a, _ = enrolled(store)
    _, _, item_b, _ = enrolled(store)
    store.arm(item_a, [])
    store.arm(item_b, [])
    matcher = Matcher(keys.match, store)
    matches = matcher.process(parse_tx(build_tx([(PREV, 0)], [COLD])))
    assert set(matches) == {Match(item_a, Direction.INCOMING), Match(item_b, Direction.INCOMING)}


def test_a_baseline_coin_spent_later_raises_the_alarm(store, keys):
    """The reason `arm` exists: coins the address held *before* enrolment."""
    _, _, item_id, _ = enrolled(store)
    store.arm(item_id, [outpoint_hmac(keys.match, PREV, 7)])
    matcher = Matcher(keys.match, store)
    assert matcher.process(parse_tx(build_tx([(PREV, 7)], [spk(0x11)]))) == (
        Match(item_id, Direction.OUTGOING),
    )


# ── purge ───────────────────────────────────────────────────────────────────────────────────


def test_purge_removes_the_tenant_and_the_bytes(db_path, keys):
    with Store(db_path, keys) as store:
        token, watch_id, item_id, _ = enrolled(store)
        store.arm(item_id, [outpoint_hmac(keys.match, PREV, 0)])
        spk_ct = store._db.execute(
            "SELECT spk_ct FROM watch_item WHERE id = ?", (item_id,)
        ).fetchone()[0]
        token_hash = hashlib.sha256(token).digest()
        store.purge_watch(watch_id)
        assert store.watch_by_token(token) is None
        with pytest.raises(UnknownRow):
            store.item(item_id)
        assert store.items_owning_outpoint(outpoint_hmac(keys.match, PREV, 0)) == ()
        assert store.channels_for(item_id) == ()
        # Measured while the connection is still open: a service never closes it, and closing
        # is what deletes the WAL -- so a check made only after close cannot see the WAL copy.
        live = file_bytes(db_path)
        assert spk_ct not in live
        assert token_hash not in live
    data = file_bytes(db_path)
    assert spk_ct not in data
    assert token_hash not in data


def test_a_purge_a_reader_blocks_is_not_reported_as_done(db_path, keys):
    """While another connection holds a read snapshot the WAL cannot be truncated, and the
    tenant's old pages are still in it. Saying "purged" then would be a false statement."""
    with Store(db_path, keys) as store:
        _, watch_id, _, _ = enrolled(store)
        reader = sqlite3.connect(db_path)
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM watch").fetchone()
            with pytest.raises(PurgeIncomplete):
                store.purge_watch(watch_id)
        finally:
            reader.close()


def test_a_purged_tenants_ids_are_never_issued_again(store):
    """Without AUTOINCREMENT SQLite reuses the highest id once its row is gone. An item or
    channel id still held in memory by the block path or a delivery would then resolve to
    the next tenant's record -- and decrypt the next tenant's destination."""
    enrolled(store)  # a tenant that stays, so the purged one is not the only row
    _, watch_id, item_id, channel_id = enrolled(store)
    store.purge_watch(watch_id)
    _, new_watch_id, new_item_id, new_channel_id = enrolled(store)
    assert new_watch_id > watch_id
    assert new_item_id > item_id
    assert new_channel_id > channel_id


def test_purge_unknown_watch_is_unknown(store):
    with pytest.raises(UnknownRow):
        store.purge_watch(77)


def test_reopening_the_file_keeps_the_record(db_path, keys):
    with Store(db_path, keys) as store:
        token, _, item_id, _ = enrolled(store)
        store.arm(item_id, [outpoint_hmac(keys.match, PREV, 1)])
    with Store(db_path, keys) as store:
        assert store.watch_by_token(token) is not None
        assert store.item(item_id).status is ItemStatus.ARMED
        assert store.outpoint_count(item_id) == 1


def test_a_different_master_cannot_read_the_file(db_path, keys):
    with Store(db_path, keys) as store:
        _, _, item_id, _ = enrolled(store)
    other_keys = derive_subkeys(b"another-master-secret-of-32-bytes")
    with Store(db_path, other_keys) as other, pytest.raises(AuthenticationFailed):
        other.item_spk(item_id)


def test_schema_is_versioned(store):
    assert store._db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_a_coin_seen_for_a_purged_item_is_dropped_not_raised(store, keys):
    """The loop looks the item up, releases the lock, then writes. If the tenant purged
    itself in between, the write must be a no-op -- a foreign-key error here comes out of
    the block path and stops every tenant's watcher."""
    _, watch_id, item_id, _ = enrolled(store)
    store.arm(item_id, [])
    store.purge_watch(watch_id)
    store.add_outpoint(item_id, outpoint_hmac(keys.match, PREV, 0))  # must not raise
    store.drop_outpoint(item_id, outpoint_hmac(keys.match, PREV, 0))


def test_a_coin_seen_for_a_stopped_item_is_not_recorded(store, keys):
    """Same window, other outcome: a coin recorded against a stopped item would later match
    as a spend nobody asked to be told about."""
    _, _, item_id, _ = enrolled(store)
    store.arm(item_id, [])
    store.stop_item(item_id)
    coin = outpoint_hmac(keys.match, PREV, 0)
    store.add_outpoint(item_id, coin)
    assert store.items_owning_outpoint(coin) == ()


def test_a_coin_seen_for_an_arming_item_is_not_recorded(store, keys):
    """The baseline owns the record until `arm`; a stray write before it would be doubled
    or, worse, be a coin the baseline then reports as still unspent."""
    _, _, item_id, _ = enrolled(store)
    coin = outpoint_hmac(keys.match, PREV, 0)
    store.add_outpoint(item_id, coin)
    assert store.outpoint_count(item_id) == 0


def test_a_newer_schema_is_refused(db_path, keys):
    with Store(db_path, keys):
        pass
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA user_version=99")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError):
        Store(db_path, keys)


def test_reads_from_several_threads_raise_no_thread_affinity_error(store):
    """Only that: sqlite3's default `check_same_thread` would raise here. It does not
    exercise the lock, which guards write interleaving and has no deterministic test."""
    import threading

    _, _, item_id, _ = enrolled(store)
    errors: list[BaseException] = []

    def work():
        try:
            for _ in range(50):
                store.item(item_id)
        except BaseException as exc:  # noqa: BLE001 -- we want to see anything
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_foreign_keys_are_enforced(store):
    with pytest.raises(sqlite3.IntegrityError), store._db:
        store._db.execute(
            "INSERT INTO utxo (item_id, outpoint_hmac) VALUES (?, ?)", (123, b"x" * 32)
        )


def test_the_default_clock_is_days_not_seconds(keys):
    import time

    with Store(":memory:", keys) as store:
        before = int(time.time() // 86400)
        _, watch_id = store.create_watch()
        after = int(time.time() // 86400)
        created = store._db.execute(
            "SELECT created_at FROM watch WHERE id = ?", (watch_id,)
        ).fetchone()[0]
    assert before <= created <= after
