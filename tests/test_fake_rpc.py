"""The hand-driving fixture has to model a node that *holds* coins, or it proves nothing.

`tools/fake_rpc.py` is not shipped code, so this is a short suite with one job: keep the
behaviours reconciliation depends on from rotting. Until now its `scantxoutset` answered
`"unspents": []` unconditionally, which is indistinguishable from a node that lost everything
— so a reconciler driven against it would have looked like it worked while never once being
asked to repair a real divergence.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import fake_rpc

SPK_A = "0014" + "aa" * 20
SPK_B = "0014" + "bb" * 20
TXID_1 = "11" * 32
TXID_2 = "22" * 32


def call(method: str, *params: object, scan_delay: float = 0.0):
    """One RPC round trip, unwrapped. Raises on an error reply so a test cannot ignore one."""
    result, error = fake_rpc.handle(method, list(params), scan_delay)
    if error is not None:
        raise AssertionError(f"rpc error: {error}")
    return result


@pytest.fixture(autouse=True)
def clean_chainstate():
    """Module globals, so state leaks between tests unless it is reset. It is a fixture, not a
    refactor to a class, because the HTTP handler reads those globals and the point of this
    module is to test what the tool actually does."""
    fake_rpc._utxos = {}
    fake_rpc._height = fake_rpc.TIP_HEIGHT
    fake_rpc._scan = None
    yield
    fake_rpc._utxos = {}
    fake_rpc._height = fake_rpc.TIP_HEIGHT
    fake_rpc._scan = None


def descriptor(spk: str) -> str:
    return f"raw({spk})"


def scan(*spks: str) -> dict:
    return call("scantxoutset", "start", [descriptor(s) for s in spks])


def test_scan_reports_seeded_coins_and_only_those_asked_for():
    call("_fake_receive", [
        {"spk": SPK_A, "txid": TXID_1, "vout": 0},
        {"spk": SPK_B, "txid": TXID_2, "vout": 7},
    ])

    result = scan(SPK_A)

    assert result["success"] is True
    assert [(u["txid"], u["vout"], u["scriptPubKey"]) for u in result["unspents"]] == [
        (TXID_1, 0, SPK_A)
    ]


def test_a_spent_coin_leaves_the_set():
    call("_fake_receive", [{"spk": SPK_A, "txid": TXID_1, "vout": 0},
                           {"spk": SPK_A, "txid": TXID_2, "vout": 1}])

    assert call("_fake_spend", [{"txid": TXID_1, "vout": 0}]) == 1

    assert [u["txid"] for u in scan(SPK_A)["unspents"]] == [TXID_2]


def test_spending_a_coin_that_is_not_there_reports_zero_rather_than_failing():
    # A reconciliation drill spends the same coin twice by mistake constantly. The honest
    # answer is "nothing moved", not an exception that reads like the tool is broken.
    assert call("_fake_spend", [{"txid": TXID_1, "vout": 0}]) == 0


def test_advancing_the_tip_changes_height_and_bestblock():
    before = scan(SPK_A)
    call("_fake_advance", 2)
    after = scan(SPK_A)

    assert after["height"] == before["height"] + 2
    assert after["bestblock"] != before["bestblock"]
    assert call("getblockcount") == after["height"]
    assert call("getbestblockhash") == after["bestblock"]


def test_the_snapshot_is_read_after_the_scan_finishes():
    """A real scan reports the chainstate it *finished* on. 186 seconds is long enough for a
    coin to be spent underneath it, and a fixture that answered from the start of the call
    would hide every ordering bug that fact creates."""
    call("_fake_receive", [{"spk": SPK_A, "txid": TXID_1, "vout": 0}])

    import threading

    def spend_during_the_scan():
        call("_fake_spend", [{"txid": TXID_1, "vout": 0}])

    timer = threading.Timer(0.05, spend_during_the_scan)
    timer.start()
    try:
        result = call("scantxoutset", "start", [descriptor(SPK_A)], scan_delay=0.4)
    finally:
        timer.cancel()

    assert result["unspents"] == []


def test_unknown_descriptor_forms_are_ignored_rather_than_guessed():
    call("_fake_receive", [{"spk": SPK_A, "txid": TXID_1, "vout": 0}])

    result = call("scantxoutset", "start", [f"addr(bc1q{'a' * 38})"])

    assert result["unspents"] == []


def test_fake_control_methods_are_prefixed_so_they_cannot_be_mistaken_for_bitcoind():
    # Service code calling one of these must fail against a real node, not work here and
    # break there. The prefix is the whole mechanism, so it is worth a test.
    assert all(
        name.startswith("_fake_")
        for name in ("_fake_receive", "_fake_spend", "_fake_advance", "_fake_utxos")
    )
    _, error = fake_rpc.handle("fake_receive", [], 0.0)
    assert error is not None and error["code"] == -32601


def test_utxo_dump_round_trips_what_was_put_in():
    coins = [{"spk": SPK_A, "txid": TXID_1, "vout": 0},
             {"spk": SPK_B, "txid": TXID_2, "vout": 3}]
    call("_fake_receive", coins)

    assert call("_fake_utxos") == sorted(coins, key=lambda c: (c["spk"], c["txid"], c["vout"]))


def test_seed_file_loads(tmp_path: Path):
    import json

    path = tmp_path / "coins.json"
    path.write_text(json.dumps([{"spk": SPK_A, "txid": TXID_1, "vout": 4}]))

    assert fake_rpc._load_utxos(path) == {SPK_A: {(TXID_1, 4)}}
