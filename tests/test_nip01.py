"""NIP-01 event id / Schnorr signing -- checked against real events from 59.md's worked example.

`tests/fixtures/nip59_example.json` is extracted programmatically from the NIP-59 spec's own
"An Example" section, not hand-copied -- see nip01.py's module docstring for why that matters.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from coldwatch.channels.nostr.nip01 import (
    event_id,
    pubkey_hex_from_privkey,
    sign_event_id,
    verify_event_sig,
)

EXAMPLE = json.loads((Path(__file__).parent / "fixtures" / "nip59_example.json").read_text())


def test_rumor_id_matches_the_spec_doc():
    rumor = EXAMPLE["rumor"]
    got = event_id(rumor["pubkey"], rumor["created_at"], rumor["kind"], rumor["tags"], rumor["content"])
    assert got == rumor["id"]


def test_seal_id_matches_the_spec_doc():
    seal = EXAMPLE["seal"]
    got = event_id(seal["pubkey"], seal["created_at"], seal["kind"], seal["tags"], seal["content"])
    assert got == seal["id"]


def test_wrap_id_matches_the_spec_doc():
    wrap = EXAMPLE["wrap"]
    got = event_id(wrap["pubkey"], wrap["created_at"], wrap["kind"], wrap["tags"], wrap["content"])
    assert got == wrap["id"]


def test_seal_sig_verifies_against_a_real_cross_implementation_signature():
    """The doc's seal was signed by nostr-tools (JS), not this module -- this proves
    `verify_event_sig` actually interoperates, not just that it agrees with itself."""
    seal = EXAMPLE["seal"]
    assert verify_event_sig(seal["pubkey"], seal["id"], seal["sig"]) is True


def test_wrap_sig_verifies_against_a_real_cross_implementation_signature():
    wrap = EXAMPLE["wrap"]
    assert verify_event_sig(wrap["pubkey"], wrap["id"], wrap["sig"]) is True


def test_pubkey_from_privkey_matches_the_doc():
    assert pubkey_hex_from_privkey(EXAMPLE["keys"]["Author"]) == EXAMPLE["rumor"]["pubkey"]
    assert pubkey_hex_from_privkey(EXAMPLE["keys"]["Recipient"])  # just must not raise


def test_self_signed_round_trip_verifies():
    sk = secrets.token_bytes(32).hex()
    pk = pubkey_hex_from_privkey(sk)
    eid = event_id(pk, 1700000000, 14, [["p", "ab" * 32]], "hello")
    sig = sign_event_id(sk, eid)
    assert verify_event_sig(pk, eid, sig) is True


def test_tampered_content_does_not_verify():
    sk = secrets.token_bytes(32).hex()
    pk = pubkey_hex_from_privkey(sk)
    eid = event_id(pk, 1700000000, 14, [["p", "ab" * 32]], "hello")
    sig = sign_event_id(sk, eid)
    tampered_id = event_id(pk, 1700000000, 14, [["p", "ab" * 32]], "goodbye")
    assert verify_event_sig(pk, tampered_id, sig) is False


def test_verify_rejects_malformed_input_rather_than_raising():
    assert verify_event_sig("not hex", "also not hex", "nor this") is False
