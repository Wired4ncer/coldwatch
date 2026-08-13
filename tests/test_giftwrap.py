"""NIP-59/17 gift wrap -- verified by decrypting 59.md's own real worked example end to end,
then round-tripping a freshly built rumor/seal/wrap through the same keys.
"""

from __future__ import annotations

import json
from pathlib import Path

from coldwatch.channels.nostr import giftwrap, nip01, nip44

EXAMPLE = json.loads((Path(__file__).parent / "fixtures" / "nip59_example.json").read_text())


def _unwrap(wrap: dict, recipient_privkey_hex: str) -> dict:
    conversation_key = nip44.get_conversation_key(recipient_privkey_hex, wrap["pubkey"])
    return json.loads(nip44.decrypt(wrap["content"], conversation_key))


def _unseal(seal: dict, recipient_privkey_hex: str) -> dict:
    conversation_key = nip44.get_conversation_key(recipient_privkey_hex, seal["pubkey"])
    return json.loads(nip44.decrypt(seal["content"], conversation_key))


def test_decrypts_the_real_cross_implementation_wrap_from_the_spec_doc():
    """The doc's wrap was produced entirely by nostr-tools (JS) -- decrypting it here proves
    interop, not just internal self-consistency."""
    recipient_sk = EXAMPLE["keys"]["Recipient"]

    recovered_seal = _unwrap(EXAMPLE["wrap"], recipient_sk)
    assert recovered_seal["id"] == EXAMPLE["seal"]["id"]

    recovered_rumor = _unseal(recovered_seal, recipient_sk)
    assert recovered_rumor["id"] == EXAMPLE["rumor"]["id"]
    assert recovered_rumor["content"] == EXAMPLE["rumor"]["content"]

    # NIP-17's anti-impersonation check: the seal's pubkey must equal the rumor's pubkey.
    assert recovered_seal["pubkey"] == recovered_rumor["pubkey"]


def test_self_built_round_trip():
    author_sk = EXAMPLE["keys"]["Author"]
    recipient_sk = EXAMPLE["keys"]["Recipient"]
    recipient_pk = nip01.pubkey_hex_from_privkey(recipient_sk)

    rumor = giftwrap.make_rumor(author_sk, recipient_pk, "testing coldwatch's own gift wrap")
    seal = giftwrap.make_seal(rumor, author_sk, recipient_pk)
    wrap = giftwrap.make_wrap(seal, recipient_pk)

    round_trip_seal = _unwrap(wrap, recipient_sk)
    round_trip_rumor = _unseal(round_trip_seal, recipient_sk)
    assert round_trip_rumor["content"] == rumor["content"]
    assert round_trip_rumor["id"] == rumor["id"]


def test_seal_is_signed_by_the_real_sender_not_the_ephemeral_key():
    author_sk = EXAMPLE["keys"]["Author"]
    recipient_pk = nip01.pubkey_hex_from_privkey(EXAMPLE["keys"]["Recipient"])

    rumor = giftwrap.make_rumor(author_sk, recipient_pk, "hello")
    seal = giftwrap.make_seal(rumor, author_sk, recipient_pk)
    assert seal["pubkey"] == nip01.pubkey_hex_from_privkey(author_sk)
    assert nip01.verify_event_sig(seal["pubkey"], seal["id"], seal["sig"]) is True


def test_wrap_is_signed_by_a_fresh_ephemeral_key_each_time():
    author_sk = EXAMPLE["keys"]["Author"]
    recipient_pk = nip01.pubkey_hex_from_privkey(EXAMPLE["keys"]["Recipient"])

    rumor = giftwrap.make_rumor(author_sk, recipient_pk, "hello")
    seal = giftwrap.make_seal(rumor, author_sk, recipient_pk)
    wrap_a = giftwrap.make_wrap(seal, recipient_pk)
    wrap_b = giftwrap.make_wrap(seal, recipient_pk)

    assert wrap_a["pubkey"] != wrap_b["pubkey"]
    assert wrap_a["pubkey"] != nip01.pubkey_hex_from_privkey(author_sk)
    assert nip01.verify_event_sig(wrap_a["pubkey"], wrap_a["id"], wrap_a["sig"]) is True


def test_seal_tags_are_always_empty():
    author_sk = EXAMPLE["keys"]["Author"]
    recipient_pk = nip01.pubkey_hex_from_privkey(EXAMPLE["keys"]["Recipient"])
    rumor = giftwrap.make_rumor(author_sk, recipient_pk, "hello")
    seal = giftwrap.make_seal(rumor, author_sk, recipient_pk)
    assert seal["tags"] == []


def test_wrap_carries_exactly_one_p_tag_for_the_recipient():
    author_sk = EXAMPLE["keys"]["Author"]
    recipient_pk = nip01.pubkey_hex_from_privkey(EXAMPLE["keys"]["Recipient"])
    rumor = giftwrap.make_rumor(author_sk, recipient_pk, "hello")
    seal = giftwrap.make_seal(rumor, author_sk, recipient_pk)
    wrap = giftwrap.make_wrap(seal, recipient_pk)
    assert wrap["tags"] == [["p", recipient_pk]]


def test_rumor_is_unsigned():
    author_sk = EXAMPLE["keys"]["Author"]
    recipient_pk = nip01.pubkey_hex_from_privkey(EXAMPLE["keys"]["Recipient"])
    rumor = giftwrap.make_rumor(author_sk, recipient_pk, "hello")
    assert "sig" not in rumor
