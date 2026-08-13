"""ChaCha20 -- checked against RFC 8439's own published test vectors."""

from __future__ import annotations

from coldwatch.channels.nostr.chacha20 import chacha20_xor


# RFC 8439 §2.3.2: the raw keystream block for counter=1 (XORing an all-zero plaintext with
# the keystream yields the keystream itself).
def test_block_keystream_matches_rfc8439_2_3_2():
    key = bytes(range(0x20))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected_keystream = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert chacha20_xor(key, nonce, b"\x00" * 64, counter=1) == expected_keystream


# RFC 8439 §2.4.2: the full "Sunscreen" encryption example.
def test_sunscreen_vector_matches_rfc8439_2_4_2():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    expected_ciphertext = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    assert len(plaintext) == 114
    assert chacha20_xor(key, nonce, plaintext, counter=1) == expected_ciphertext


def test_encrypt_then_encrypt_is_decrypt():
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"round trip through the same keystream"
    ciphertext = chacha20_xor(key, nonce, plaintext)
    assert chacha20_xor(key, nonce, ciphertext) == plaintext


def test_different_counters_produce_different_keystreams():
    key = bytes(range(32))
    nonce = bytes(range(12))
    data = b"\x00" * 64
    assert chacha20_xor(key, nonce, data, counter=0) != chacha20_xor(key, nonce, data, counter=1)
