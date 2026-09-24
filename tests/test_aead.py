"""ChaCha20-Poly1305 AEAD -- RFC 8439's vectors first, then the properties storage relies on."""

from __future__ import annotations

import pytest

from coldwatch.crypto import AuthenticationFailed, open_, seal
from coldwatch.crypto.aead import NONCE_LEN, TAG_LEN, _seal_with_nonce

KEY = bytes(range(0x80, 0xA0))
AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
NONCE = bytes.fromhex("070000004041424344454647")
PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
    b"future, sunscreen would be it."
)
CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
)
TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")


# RFC 8439 §2.8.2.
def test_rfc8439_2_8_2_seal():
    sealed = _seal_with_nonce(KEY, NONCE, PLAINTEXT, AAD)
    assert sealed == NONCE + CIPHERTEXT + TAG


def test_rfc8439_2_8_2_open():
    assert open_(KEY, NONCE + CIPHERTEXT + TAG, AAD) == PLAINTEXT


# RFC 8439 A.5: a decryption vector with a different key, nonce and a long aad.
def test_rfc8439_a5_open():
    key = bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
    nonce = bytes.fromhex("000000000102030405060708")
    aad = bytes.fromhex("f33388860000000000004e91")
    ciphertext = bytes.fromhex(
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
        "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
        "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
        "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
        "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
        "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
        "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
        "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
        "a6ad5cb4022b02709b"
    )
    tag = bytes.fromhex("eead9d67890cbb22392336fea1851f38")
    expected = (
        b"Internet-Drafts are draft documents valid for a maximum of six months and may be "
        b"updated, replaced, or obsoleted by other documents at any time. It is inappropriate "
        b"to use Internet-Drafts as reference material or to cite them other than as /\xe2\x80\x9c"
        b"work in progress./\xe2\x80\x9d"
    )
    assert open_(key, nonce + ciphertext + tag, aad) == expected


def test_seal_is_randomised():
    a = seal(KEY, b"same", b"aad")
    b = seal(KEY, b"same", b"aad")
    assert a != b
    assert a[:NONCE_LEN] != b[:NONCE_LEN]
    assert open_(KEY, a, b"aad") == open_(KEY, b, b"aad") == b"same"


def test_layout_is_nonce_ciphertext_tag():
    sealed = seal(KEY, b"abc")
    assert len(sealed) == NONCE_LEN + 3 + TAG_LEN


@pytest.mark.parametrize("position", ["nonce", "ciphertext", "tag"])
def test_any_flipped_bit_is_refused(position):
    sealed = bytearray(seal(KEY, PLAINTEXT, AAD))
    index = {"nonce": 0, "ciphertext": NONCE_LEN, "tag": len(sealed) - 1}[position]
    sealed[index] ^= 0x01
    with pytest.raises(AuthenticationFailed):
        open_(KEY, bytes(sealed), AAD)


def test_wrong_aad_is_refused():
    sealed = seal(KEY, b"spk bytes", b"spk")
    with pytest.raises(AuthenticationFailed):
        open_(KEY, sealed, b"dest")


def test_wrong_key_is_refused():
    sealed = seal(KEY, b"x", b"")
    with pytest.raises(AuthenticationFailed):
        open_(bytes(32), sealed, b"")


def test_truncated_is_refused_not_indexed():
    with pytest.raises(AuthenticationFailed):
        open_(KEY, bytes(NONCE_LEN + TAG_LEN - 1), b"")


def test_empty_plaintext_round_trips():
    assert open_(KEY, seal(KEY, b"", b"aad"), b"aad") == b""


def test_key_length_is_enforced():
    with pytest.raises(ValueError):
        seal(bytes(16), b"x")
    with pytest.raises(ValueError):
        open_(bytes(16), bytes(64))
