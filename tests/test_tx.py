"""Transaction parsing, including the segwit path the fixtures do not cover.

The recorded fixtures are witness-free, so parsing them proves less than it looks. A live node
publishes segwit transactions constantly, and the witness-stripping rule for txids is exactly
the sort of thing that works on every test and then quietly mismatches in production. So the
transactions here are built in the test, and the segwit path is checked against its own
legacy twin rather than against an assumption.

Everything is synthetic. No real address, no real transaction, nothing that existed on any
chain — CONTRIBUTING.md §4.
"""

from __future__ import annotations

import dataclasses
import struct

import pytest

from coldwatch.match import MalformedTransaction, parse_tx
from coldwatch.match.tx import COINBASE_VOUT, NULL_TXID
from support import PREV, build_tx, dsha256, spk, varint

# ── the shape of a parsed transaction ───────────────────────────────────────────────────────


def test_inputs_and_outputs_are_extracted():
    raw = build_tx([(PREV, 3)], [spk(0xAA), spk(0xBB)])
    tx = parse_tx(raw)

    assert [(i.txid, i.vout) for i in tx.inputs] == [(PREV, 3)]
    assert [(o.vout, o.spk) for o in tx.outputs] == [(0, spk(0xAA)), (1, spk(0xBB))]
    assert tx.has_witness is False
    assert tx.is_coinbase is False


def test_output_index_is_the_position_in_the_transaction():
    """`vout` is positional. Deriving it any other way produces outpoints that look right and
    match nothing."""
    tx = parse_tx(build_tx([(PREV, 0)], [spk(1), spk(2), spk(3)]))
    assert [o.vout for o in tx.outputs] == [0, 1, 2]


def test_a_parsed_transaction_carries_no_amount():
    """Invariant I2 starts here: a field that is never parsed out cannot be threaded into a
    template later 'just for context'."""
    tx = parse_tx(build_tx([(PREV, 0)], [spk(1)]))
    names = {f.name for f in dataclasses.fields(tx.outputs[0])}
    names |= {f.name for f in dataclasses.fields(tx.inputs[0])}
    for forbidden in ("value", "amount", "sats", "satoshi"):
        assert not any(forbidden in name.lower() for name in names)


# ── segwit ──────────────────────────────────────────────────────────────────────────────────


def test_segwit_and_legacy_forms_of_one_transaction_share_a_txid():
    """The property that matters, checked without restating the stripping rule.

    A txid is the hash of the witness-stripped serialisation. If the parser hashed the raw
    bytes instead, these two would differ — and the failure in production would be a watched
    output never being added to the UTXO set, i.e. a watch that silently stops alarming.
    """
    inputs, outputs = [(PREV, 1)], [spk(0xCD)]
    segwit = build_tx(inputs, outputs, witness=[[b"\x30" * 71, b"\x02" * 33]])
    legacy = build_tx(inputs, outputs)

    parsed = parse_tx(segwit)
    assert parsed.has_witness is True
    assert parsed.txid == parse_tx(legacy).txid == dsha256(legacy)


def test_witness_data_does_not_change_the_txid():
    """Witness malleability: a third party can alter the witness of an unconfirmed
    transaction. The identifier we key the UTXO set on must not move when they do."""
    inputs, outputs = [(PREV, 1)], [spk(0xCD)]
    a = parse_tx(build_tx(inputs, outputs, witness=[[b"\x30" * 71]]))
    b = parse_tx(build_tx(inputs, outputs, witness=[[b"\x99" * 64, b"\x01"]]))
    assert a.txid == b.txid


def test_multi_input_witness_is_consumed_in_full():
    """Each input has its own witness stack. Miscounting leaves bytes over, and the trailing
    check turns that into a loud failure rather than a wrong txid."""
    tx = parse_tx(
        build_tx(
            [(PREV, 0), (PREV, 1)],
            [spk(7)],
            witness=[[b"\x30" * 71, b"\x02" * 33], []],
        )
    )
    assert len(tx.inputs) == 2


def test_a_zero_flag_is_not_a_segwit_marker():
    raw = struct.pack("<I", 2) + b"\x00\x00" + varint(1)
    with pytest.raises(MalformedTransaction):
        parse_tx(raw)


# ── coinbase ────────────────────────────────────────────────────────────────────────────────


def test_a_coinbase_spends_nothing():
    """Its input references an outpoint that does not exist. Looking that up would be a
    lookup per block for a value no watch can own — and worse, a hit would mean the loop
    believed something was spent when nothing was."""
    tx = parse_tx(build_tx([(NULL_TXID, COINBASE_VOUT)], [spk(9)], script_sig=b"\x03\x01\x02"))
    assert tx.is_coinbase is True
    assert tx.inputs == ()
    assert len(tx.outputs) == 1


def test_a_normal_transaction_is_not_mistaken_for_a_coinbase():
    assert parse_tx(build_tx([(PREV, COINBASE_VOUT)], [spk(9)])).is_coinbase is False
    assert parse_tx(build_tx([(NULL_TXID, 0)], [spk(9)])).is_coinbase is False


# ── malformed input ─────────────────────────────────────────────────────────────────────────


def test_truncation_is_rejected_rather_than_parsed_short():
    raw = build_tx([(PREV, 0)], [spk(1), spk(2)])
    for cut in (5, 20, 60, len(raw) - 1):
        with pytest.raises(MalformedTransaction):
            parse_tx(raw[:cut])


def test_trailing_bytes_are_rejected():
    """Extra bytes mean the parse diverged somewhere upstream, and a txid computed over a
    misparsed buffer is worse than no txid at all."""
    with pytest.raises(MalformedTransaction):
        parse_tx(build_tx([(PREV, 0)], [spk(1)]) + b"\x00")


def test_a_transaction_with_no_inputs_is_rejected():
    raw = struct.pack("<I", 2) + varint(0) + varint(0) + struct.pack("<I", 0)
    with pytest.raises(MalformedTransaction):
        parse_tx(raw)


def test_an_absurd_element_count_fails_immediately():
    """A corrupt length claiming billions of inputs must not cost a loop over them."""
    raw = struct.pack("<I", 2) + b"\xfe\xff\xff\xff\xff"
    with pytest.raises(MalformedTransaction):
        parse_tx(raw)


def test_empty_input_is_rejected():
    with pytest.raises(MalformedTransaction):
        parse_tx(b"")


# ── against the recorded stream ─────────────────────────────────────────────────────────────


def test_every_fixture_transaction_parses(contiguous_stream):
    for message in contiguous_stream:
        tx = parse_tx(message.body)
        assert len(tx.inputs) == 1
        assert len(tx.outputs) == 2
        assert all(o.spk.startswith(b"\x00\x14") and len(o.spk) == 22 for o in tx.outputs)


def test_fixture_txids_are_distinct(contiguous_stream):
    """120 distinct transactions. Identical txids would mean the parser is hashing something
    constant, which every other test here would still pass."""
    txids = {parse_tx(m.body).txid for m in contiguous_stream}
    assert len(txids) == len(contiguous_stream)
