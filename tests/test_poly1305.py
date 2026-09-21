"""Poly1305 -- checked against RFC 8439's own published test vectors."""

from __future__ import annotations

import pytest

from coldwatch.crypto.poly1305 import poly1305_mac


# RFC 8439 §2.5.2.
def test_rfc8439_2_5_2():
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    message = b"Cryptographic Forum Research Group"
    assert poly1305_mac(key, message) == bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")


# RFC 8439 A.3, vector #1: an all-zero key over an all-zero message.
def test_rfc8439_a3_zero_key():
    assert poly1305_mac(bytes(32), bytes(64)) == bytes(16)


# RFC 8439 A.3, vector #2: r = 0, so the tag is s regardless of the message.
def test_rfc8439_a3_vector_2():
    key = bytes.fromhex(
        "00000000000000000000000000000000"
        "36e5f6b5c5e06070f0efca96227a863e"
    )
    message = (
        b"Any submission to the IETF intended by the Contributor for publication as all or "
        b"part of an IETF Internet-Draft or RFC and any statement made within the context of "
        b"an IETF activity is considered an \"IETF Contribution\". Such statements include "
        b"oral statements in IETF sessions, as well as written and electronic communications "
        b"made at any time or place, which are addressed to"
    )
    assert poly1305_mac(key, message) == bytes.fromhex("36e5f6b5c5e06070f0efca96227a863e")


# RFC 8439 A.3, vector #3: the same message with s = 0 and r = the value above.
def test_rfc8439_a3_vector_3():
    key = bytes.fromhex(
        "36e5f6b5c5e06070f0efca96227a863e"
        "00000000000000000000000000000000"
    )
    message = (
        b"Any submission to the IETF intended by the Contributor for publication as all or "
        b"part of an IETF Internet-Draft or RFC and any statement made within the context of "
        b"an IETF activity is considered an \"IETF Contribution\". Such statements include "
        b"oral statements in IETF sessions, as well as written and electronic communications "
        b"made at any time or place, which are addressed to"
    )
    assert poly1305_mac(key, message) == bytes.fromhex("f3477e7cd95417af89a6b8794c310cf0")


# RFC 8439 A.3, vector #4: a message that is not a multiple of 16 bytes, so the final block
# is short and the appended 1 bit lands mid-word.
def test_rfc8439_a3_vector_4_short_final_block():
    key = bytes.fromhex(
        "1c9240a5eb55d38af333888604f6b5f0"
        "473917c1402b80099dca5cbc207075c0"
    )
    message = (
        b"'Twas brillig, and the slithy toves\n"
        b"Did gyre and gimble in the wabe:\n"
        b"All mimsy were the borogoves,\n"
        b"And the mome raths outgrabe."
    )
    assert len(message) % 16 != 0
    assert poly1305_mac(key, message) == bytes.fromhex("4541669a7eaaee61e708dc7cbcc5eb62")


# RFC 8439 A.3, vector #5: the accumulator must wrap modulo 2^130 - 5, not 2^130.
def test_rfc8439_a3_vector_5_wraps_mod_p():
    key = bytes.fromhex(
        "02000000000000000000000000000000"
        "00000000000000000000000000000000"
    )
    message = bytes.fromhex("ffffffffffffffffffffffffffffffff")
    assert poly1305_mac(key, message) == bytes.fromhex("03000000000000000000000000000000")


def test_key_length_is_enforced():
    with pytest.raises(ValueError):
        poly1305_mac(bytes(31), b"x")


def test_empty_message_is_just_s():
    key = bytes(16) + bytes(range(16))
    assert poly1305_mac(key, b"") == bytes(range(16))
