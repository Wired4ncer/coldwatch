"""Key derivation and the keyed hashes, including the byte-order trap.

The interesting test in here is `test_display_and_internal_txid_order_are_not_interchangeable`.
Getting txid orientation wrong is the classic Bitcoin bug, and in this codebase it fails in
the worst available way: enrolment stores one orientation, the matching loop computes the
other, nothing ever matches, and the service looks perfectly healthy while watching nothing.
"""

from __future__ import annotations

import pytest

from coldwatch.match import (
    canonical_outpoint,
    derive_subkeys,
    hkdf,
    outpoint_hmac,
    spk_hmac,
    txid_from_display,
    txid_to_display,
)
from coldwatch.match.keys import MIN_MASTER_BYTES

TXID = bytes(range(32))


# ── HKDF, against the RFC ───────────────────────────────────────────────────────────────────


def test_hkdf_matches_rfc_5869_test_case_1():
    """RFC 5869 §A.1 — a documented test vector, which is what CONTRIBUTING.md §4 asks for.

    Worth having despite being stdlib HMAC underneath: the extract/expand construction is
    easy to get subtly wrong (a missing counter byte, the wrong salt default) in a way that
    still produces plausible-looking key material.
    """
    okm = hkdf(
        ikm=bytes.fromhex("0b" * 22),
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_expands_past_one_hash_block():
    """Anything over 32 bytes exercises the counter loop, which one round would not."""
    assert len(hkdf(b"master", b"info", length=100)) == 100


def test_hkdf_rejects_impossible_lengths():
    for bad in (0, -1, 255 * 32 + 1):
        with pytest.raises(ValueError):
            hkdf(b"master", b"info", length=bad)


# ── subkeys ─────────────────────────────────────────────────────────────────────────────────


def test_the_two_subkeys_differ():
    """Same master, different info strings. If these ever came out equal, a compromise of the
    constantly-in-memory match key would hand over the storage key too."""
    keys = derive_subkeys(b"m" * 32)
    assert keys.match != keys.store
    assert len(keys.match) == len(keys.store) == 32


def test_subkeys_are_deterministic():
    """Restarting the service must not orphan every HMAC written before it."""
    assert derive_subkeys(b"m" * 32) == derive_subkeys(b"m" * 32)


def test_different_masters_give_different_subkeys():
    assert derive_subkeys(b"m" * 32).match != derive_subkeys(b"n" * 32).match


def test_a_short_master_is_refused():
    with pytest.raises(ValueError):
        derive_subkeys(b"x" * (MIN_MASTER_BYTES - 1))


def test_the_short_master_error_does_not_describe_the_master():
    """The message is logged. 'master secret is 8 bytes' is a useful hint to an attacker and
    of no use to an operator, who can count it themselves."""
    with pytest.raises(ValueError) as exc:
        derive_subkeys(b"x" * 4)
    assert "4" not in str(exc.value)
    assert "x" not in str(exc.value)


# ── the keyed hashes ────────────────────────────────────────────────────────────────────────


def test_hashing_is_keyed_not_merely_hashed(k_match):
    """The whole privacy claim. Addresses come from a public, enumerable set, so an unkeyed
    hash of one is matchable by anyone willing to hash the chain. Two different keys must
    produce two different digests for the same script."""
    other = derive_subkeys(b"z" * 32).match
    script = b"\x00\x14" + b"\x11" * 20
    assert spk_hmac(k_match, script) != spk_hmac(other, script)


def test_spk_and_outpoint_hashes_are_domain_separated(k_match):
    """A 36-byte script and a canonically serialised outpoint are both just bytes. Without
    tagging, one could match the other — rare, silent, and untraceable when it happened."""
    outpoint = canonical_outpoint(TXID, 4)
    assert spk_hmac(k_match, outpoint) != outpoint_hmac(k_match, TXID, 4)


def test_the_same_input_always_hashes_the_same(k_match):
    assert spk_hmac(k_match, b"\x51") == spk_hmac(k_match, b"\x51")
    assert outpoint_hmac(k_match, TXID, 1) == outpoint_hmac(k_match, TXID, 1)


def test_vout_is_part_of_the_identity(k_match):
    """Two outputs of one transaction are different coins. Hashing only the txid would fire
    the alarm when any output was spent, watched or not."""
    assert outpoint_hmac(k_match, TXID, 0) != outpoint_hmac(k_match, TXID, 1)


# ── byte order ──────────────────────────────────────────────────────────────────────────────


def test_canonical_outpoint_is_txid_then_little_endian_vout():
    assert canonical_outpoint(TXID, 1) == TXID + b"\x01\x00\x00\x00"


def test_display_and_internal_txid_order_are_not_interchangeable(k_match):
    """The trap, stated as a test: the same txid in the two orientations is two different
    outpoints. Anything arriving as text goes through `txid_from_display` first."""
    display = txid_to_display(TXID)
    assert txid_from_display(display) == TXID
    assert bytes.fromhex(display) != TXID
    assert outpoint_hmac(k_match, bytes.fromhex(display), 0) != outpoint_hmac(k_match, TXID, 0)


def test_display_conversion_round_trips():
    assert txid_from_display(txid_to_display(TXID)) == TXID


@pytest.mark.parametrize("bad", [b"", bytes(31), bytes(33)])
def test_a_txid_must_be_thirty_two_bytes(bad):
    with pytest.raises(ValueError):
        canonical_outpoint(bad, 0)
    with pytest.raises(ValueError):
        txid_to_display(bad)


@pytest.mark.parametrize("bad", [-1, 1 << 32])
def test_vout_range_is_enforced(bad):
    with pytest.raises(ValueError):
        canonical_outpoint(TXID, bad)
