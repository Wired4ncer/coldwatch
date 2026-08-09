"""The proof script, driven offline against a fake chain.

`tools/induced_gap_proof.py` is the thing that will close issue #24 by running against a real
node with real credentials — which is precisely why it must not run for the first time *there*.
A script whose first execution is also its first test is one whose typos are discovered while
someone is holding a password at a production shell prompt.

So the script's body is importable and takes any object with `.call`, and this drives it over
the same `FakeChain` the reconciler's own tests use.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.induced_gap_proof import find_spend_within, run

from coldwatch.node.rpc import RpcError
from support import PREV, build_tx, spk
from test_reconcile import FakeChain

COLD = spk(0xC0)
OTHER = spk(0x11)


@pytest.fixture
def chain_with_a_spend() -> FakeChain:
    """Eight blocks, with a coin paid to a watched script in one and spent three later.

    The gap the script induces has to *contain* both events, or there is nothing for
    reconciliation to catch — which is the difference between this proving something and
    printing PASS eight times.
    """
    chain = FakeChain()
    chain.add([])
    chain.add([])
    funding = build_tx([(PREV, 0)], [COLD])
    chain.add([funding])          # index 2
    chain.add([])
    from coldwatch.match import parse_tx

    chain.add([build_tx([(parse_tx(funding).txid, 0)], [OTHER])])  # index 4, the spend
    chain.add([])
    chain.add([])
    chain.add([])                 # index 7, the tip
    return chain


def test_the_proof_passes_against_a_chain_that_contains_a_spend(chain_with_a_spend, capsys):
    """Exit 0, and the checks it printed are the ones that matter — asserted here rather than
    trusted, because a proof script that always passes is worse than no proof script."""
    assert run(chain_with_a_spend, blocks_back=6) == 0

    out = capsys.readouterr().out
    assert "PASS  the deposit was seen (INCOMING)" in out
    assert "PASS  the spend raised the alarm (OUTGOING)" in out
    assert "PASS  refetched exactly" in out
    assert "FAIL" not in out


class BreaksAfterTheSurvey:
    """A node that serves the survey and then stops serving blocks.

    Contrived on purpose. The failure it produces — catch-up unable to fetch what it needs —
    is the one branch that matters most, and it cannot be reached by pruning, because a prune
    deep enough to break catch-up also breaks the survey that runs first.
    """

    def __init__(self, chain, allow: int) -> None:
        self._chain = chain
        self._left = allow

    def call(self, method: str, *params: object, timeout: float | None = None) -> object:
        if method == "getblock" and params[1:] == (0,):
            if self._left <= 0:
                raise RpcError(-1, "Block not available (pruned data)")
            self._left -= 1
        return self._chain.call(method, *params, timeout=timeout)


def test_it_reports_a_repair_that_could_not_happen(chain_with_a_spend, capsys):
    """The script must be able to fail, or its PASS means nothing.

    The survey succeeds, then the node stops serving blocks, so catch-up cannot close the gap.
    The script has to say so rather than printing whatever it managed to do first.
    """
    # 7 for the survey window, 1 for the tip block it delivers. Everything after that is
    # catch-up asking for blocks it will not get.
    node = BreaksAfterTheSurvey(chain_with_a_spend, allow=8)

    assert run(node, blocks_back=6) == 1

    assert "catch-up did not close the gap" in capsys.readouterr().err


def test_a_window_below_the_prune_height_is_explained_not_raised(chain_with_a_spend, capsys):
    """A traceback at a production shell prompt, from someone who has just typed a password,
    is the worst possible moment for one."""
    chain_with_a_spend.pruned_below = chain_with_a_spend.height_of(6)

    assert run(chain_with_a_spend, blocks_back=6) == 2

    assert "prune height" in capsys.readouterr().err


def test_a_window_with_nothing_to_catch_is_reported_not_silently_passed(capsys):
    """No coin created and spent inside the window means the interesting half cannot be
    proved. That is an inconclusive run, and it must not be scored as a pass."""
    chain = FakeChain()
    for _ in range(4):
        chain.add([])

    assert run(chain, blocks_back=3) == 1
    assert "no coin in this window" in capsys.readouterr().err


def test_no_chain_data_is_printed(chain_with_a_spend, capsys):
    """Heights and counts only. Invariants I1 and I2 are not suspended because the output is a
    terminal — a terminal is where things get pasted from."""
    run(chain_with_a_spend, blocks_back=6)

    out = capsys.readouterr().out
    assert COLD.hex() not in out
    assert OTHER.hex() not in out
    for block in chain_with_a_spend.raw:
        assert block.hex() not in out
    # No 64-character hex run anywhere — that is what a txid or a block hash looks like.
    assert not any(len(word) >= 64 and _is_hex(word) for word in out.split())


def _is_hex(word: str) -> bool:
    try:
        int(word, 16)
    except ValueError:
        return False
    return True


# ── the survey step, which must not lean on the code it is checking ─────────────────────────


def test_find_spend_within_reports_the_right_pair():
    """This walks the blocks independently of the matcher, so that a bug in the matcher cannot
    make the two agree with each other and call it a proof."""
    chain = FakeChain()
    chain.add([])
    funding = build_tx([(PREV, 0)], [COLD])
    chain.add([funding])
    from coldwatch.match import parse_tx

    chain.add([build_tx([(parse_tx(funding).txid, 0)], [OTHER])])

    found = find_spend_within([chain.block(i) for i in range(3)])

    assert found is not None
    found_spk, created_index, spent_index = found
    assert (found_spk, created_index, spent_index) == (COLD, 1, 2)


def test_find_spend_within_ignores_a_coin_spent_in_its_own_block():
    """Same-block spends are real and are handled by the matching loop, but they prove nothing
    about *catch-up* — the block carrying both would have to be missed and refetched as one."""
    funding = build_tx([(PREV, 0)], [COLD])
    from coldwatch.match import parse_tx

    chain = FakeChain()
    chain.add([funding, build_tx([(parse_tx(funding).txid, 0)], [OTHER])])

    assert find_spend_within([chain.block(0)]) is None
