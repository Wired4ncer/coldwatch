"""NIP-44 v2 -- checked against the official vector file, not just internal round trips.

`tests/fixtures/nip44.vectors.json` is byte-for-byte the file published from
https://github.com/paulmillr/nip44 — its sha256 is the one 44.md itself publishes
(`269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`), checked once here so a
future accidental edit to the fixture is caught rather than silently weakening these tests.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from coldwatch.channels.nostr import nip44
from coldwatch.channels.nostr.nip01 import pubkey_hex_from_privkey

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "nip44.vectors.json"
VECTORS = json.loads(FIXTURE_PATH.read_text())["v2"]


def test_fixture_checksum_matches_the_spec():
    expected = "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040"
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("case", VECTORS["valid"]["get_conversation_key"])
def test_get_conversation_key(case):
    got = nip44.get_conversation_key(case["sec1"], case["pub2"]).hex()
    assert got == case["conversation_key"]


def test_get_message_keys():
    fixture = VECTORS["valid"]["get_message_keys"]
    conversation_key = bytes.fromhex(fixture["conversation_key"])
    for case in fixture["keys"]:
        chacha_key, chacha_nonce, hmac_key = nip44._get_message_keys(
            conversation_key, bytes.fromhex(case["nonce"])
        )
        assert chacha_key.hex() == case["chacha_key"]
        assert chacha_nonce.hex() == case["chacha_nonce"]
        assert hmac_key.hex() == case["hmac_key"]


@pytest.mark.parametrize("unpadded_len,padded_len", VECTORS["valid"]["calc_padded_len"])
def test_calc_padded_len(unpadded_len, padded_len):
    assert nip44._calc_padded_len(unpadded_len) == padded_len


@pytest.mark.parametrize("case", VECTORS["valid"]["encrypt_decrypt"])
def test_encrypt_decrypt(case):
    conversation_key = bytes.fromhex(case["conversation_key"])
    nonce = bytes.fromhex(case["nonce"])

    # The vector's own cross-check: conversation_key(sec1, pubkey-of-sec2) must match too.
    pub2 = pubkey_hex_from_privkey(case["sec2"])
    assert nip44.get_conversation_key(case["sec1"], pub2).hex() == case["conversation_key"]

    payload = nip44.encrypt(case["plaintext"], conversation_key, nonce)
    assert payload == case["payload"]
    assert nip44.decrypt(case["payload"], conversation_key) == case["plaintext"]


@pytest.mark.parametrize("case", VECTORS["valid"]["encrypt_decrypt_long_msg"])
def test_encrypt_decrypt_long_msg(case):
    conversation_key = bytes.fromhex(case["conversation_key"])
    nonce = bytes.fromhex(case["nonce"])
    plaintext = case["pattern"] * case["repeat"]
    assert hashlib.sha256(plaintext.encode()).hexdigest() == case["plaintext_sha256"]

    payload = nip44.encrypt(plaintext, conversation_key, nonce)
    assert hashlib.sha256(payload.encode()).hexdigest() == case["payload_sha256"]
    assert nip44.decrypt(payload, conversation_key) == plaintext


# The "Extended length prefix test vectors" table in 44.md itself (not in the vectors.json,
# which predates that amendment -- see nip44.py's module docstring). Exercises the boundary
# between the 2-byte and 6-byte length prefixes.
@pytest.mark.parametrize(
    "plaintext_len,expected_padded_len,plaintext_sha256,payload_sha256",
    [
        (65535, 65536,
         "6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42",
         "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84"),
        (65536, 65536,
         "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
         "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616"),
        (65537, 81920,
         "008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430",
         "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435"),
    ],
)
def test_extended_length_prefix(plaintext_len, expected_padded_len, plaintext_sha256, payload_sha256):
    conversation_key = bytes.fromhex("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
    nonce = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
    plaintext = "a" * plaintext_len
    assert hashlib.sha256(plaintext.encode()).hexdigest() == plaintext_sha256
    assert nip44._calc_padded_len(plaintext_len) == expected_padded_len

    payload = nip44.encrypt(plaintext, conversation_key, nonce)
    assert hashlib.sha256(payload.encode()).hexdigest() == payload_sha256
    assert nip44.decrypt(payload, conversation_key) == plaintext


def test_encrypt_rejects_empty_plaintext():
    with pytest.raises(ValueError):
        nip44.encrypt("", b"\x00" * 32, b"\x00" * 32)


@pytest.mark.parametrize("case", VECTORS["invalid"]["get_conversation_key"])
def test_invalid_get_conversation_key_raises(case):
    with pytest.raises(Exception):  # noqa: B017 -- the vectors span several distinct error types
        nip44.get_conversation_key(case["sec1"], case["pub2"])


@pytest.mark.parametrize("case", VECTORS["invalid"]["decrypt"])
def test_invalid_decrypt_raises(case):
    with pytest.raises(Exception):  # noqa: B017
        nip44.decrypt(case["payload"], bytes.fromhex(case["conversation_key"]))
