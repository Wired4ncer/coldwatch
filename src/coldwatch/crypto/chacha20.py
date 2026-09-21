"""ChaCha20 (RFC 8439), unauthenticated stream cipher only — no Poly1305 here.

Stdlib-only, deliberately: unlike Schnorr signing and ECDH (`nip01.py`, `nip44.py`'s
conversation-key step), ChaCha20 has no elliptic-curve arithmetic and no secret-dependent
branching or table lookups to get subtly wrong — it's addition, XOR and fixed bit-rotation on a
public counter and public nonce. NIP-44 supplies its own authentication (HMAC-SHA256 over the
ciphertext, computed in `nip44.py`), so this module never needs to be constant-time against
anything but a mistake in arithmetic, which `tests/test_chacha20.py` checks against the RFC's
own published test vectors rather than trusting this transcription.
"""

from __future__ import annotations

import struct

__all__ = ["chacha20_xor"]

_MASK32 = 0xFFFFFFFF
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl(s[b] ^ s[c], 7)


def _block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [
        *_CONSTANTS,
        *struct.unpack("<8I", key),
        counter & _MASK32,
        *struct.unpack("<3I", nonce),
    ]
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack("<16I", *((working[i] + state[i]) & _MASK32 for i in range(16)))


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """XOR `data` with the ChaCha20 keystream. Symmetric: the same call decrypts."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        keystream = _block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, keystream))
    return bytes(out)
