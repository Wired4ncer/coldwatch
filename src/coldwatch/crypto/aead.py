"""ChaCha20-Poly1305 AEAD (RFC 8439 §2.8), as the storage layer uses it.

The wire form of every ciphertext column is ``nonce(12) ‖ ciphertext ‖ tag(16)``, with the
nonce drawn fresh from `secrets` for every seal. A random 96-bit nonce is safe for the number
of ciphertexts one database will ever hold (the birthday bound is ~2^48 messages under one
key), and it has the property a counter does not: nothing has to remember where it got to,
so a restored or duplicated database cannot reuse one.

Associated data is the *purpose* of the column (`b"spk"`, `b"label"`, `b"dest"`), so a row's
`dest_ct` cannot be moved into another row's `spk_ct` and decrypt as a script. Same reasoning
as the domain tags in `match/keys.py`: cheap to prevent, tedious to debug.
"""

from __future__ import annotations

import hmac
import secrets
import struct

from coldwatch.crypto.chacha20 import chacha20_xor
from coldwatch.crypto.poly1305 import poly1305_mac

__all__ = ["NONCE_LEN", "TAG_LEN", "AuthenticationFailed", "open_", "seal"]

NONCE_LEN = 12
TAG_LEN = 16


class AuthenticationFailed(ValueError):
    """The ciphertext, its nonce, its tag or the associated data has been altered.

    Deliberately says nothing about which -- a distinguishable failure is an oracle -- and
    deliberately carries no bytes: the message ends up in a log.
    """


def _pad16(data: bytes) -> bytes:
    return bytes(-len(data) % 16)


def _tag(otk: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    # §2.8: the MAC covers aad ‖ pad ‖ ciphertext ‖ pad ‖ len(aad) ‖ len(ciphertext), both
    # lengths as 64-bit little-endian. Padding each part to a 16-byte boundary is what stops
    # the boundary between them from being movable.
    mac_data = (
        aad + _pad16(aad)
        + ciphertext + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    return poly1305_mac(otk, mac_data)


def _seal_with_nonce(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    # §2.6: the one-time Poly1305 key is the first 32 bytes of the keystream at counter 0;
    # the plaintext is then encrypted from counter 1, so the two never share keystream.
    otk = chacha20_xor(key, nonce, bytes(32), counter=0)
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    return nonce + ciphertext + _tag(otk, aad, ciphertext)


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate. Two seals of the same input never produce the same bytes."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    return _seal_with_nonce(key, secrets.token_bytes(NONCE_LEN), plaintext, aad)


def open_(key: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Verify then decrypt. Raises `AuthenticationFailed` before touching the plaintext."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(sealed) < NONCE_LEN + TAG_LEN:
        raise AuthenticationFailed("sealed value too short")
    nonce = sealed[:NONCE_LEN]
    ciphertext = sealed[NONCE_LEN:-TAG_LEN]
    tag = sealed[-TAG_LEN:]
    otk = chacha20_xor(key, nonce, bytes(32), counter=0)
    if not hmac.compare_digest(_tag(otk, aad, ciphertext), tag):
        raise AuthenticationFailed("authentication failed")
    return chacha20_xor(key, nonce, ciphertext, counter=1)
