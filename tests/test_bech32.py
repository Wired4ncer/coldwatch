"""bech32 (NIP-19 npub) -- checked against 19.md's own worked examples, not just round trips."""

from __future__ import annotations

import pytest

from coldwatch.channels.nostr.bech32 import decode_npub, encode_npub

# Straight from NIP-19's "Examples" and "Bare keys and ids" sections.
VECTORS = [
    (
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
    ),
    (
        "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
    ),
]


@pytest.mark.parametrize("hexkey,npub", VECTORS)
def test_encode_matches_nip19_vector(hexkey, npub):
    assert encode_npub(bytes.fromhex(hexkey)) == npub


@pytest.mark.parametrize("hexkey,npub", VECTORS)
def test_decode_matches_nip19_vector(hexkey, npub):
    assert decode_npub(npub) == bytes.fromhex(hexkey)


def test_round_trip():
    pubkey = bytes(range(32))
    assert decode_npub(encode_npub(pubkey)) == pubkey


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "npub1",
        "nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",  # wrong prefix
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7",  # bad checksum
        "not even close to bech32",
        "npub1" + "q" * 100,  # garbage data, no valid checksum
    ],
)
def test_decode_rejects_junk(bad):
    with pytest.raises(ValueError):
        decode_npub(bad)


def test_encode_rejects_wrong_length():
    with pytest.raises(ValueError):
        encode_npub(b"\x00" * 31)
    with pytest.raises(ValueError):
        encode_npub(b"\x00" * 33)
