"""Poly1305 (RFC 8439 §2.5), the one-time authenticator under the storage AEAD.

Not constant-time, and that is a stated property rather than an oversight: Python integers
are arbitrary-precision and their arithmetic leaks operand size. The tag is only ever
*verified* against data read back from our own database, where the only party that could feed
chosen ciphertexts and time the reply already holds the process -- and with it the key. The
comparison itself still goes through `hmac.compare_digest` in `aead.py`, because that costs
nothing and closes the one timing channel that is cheap to close.

Checked against the RFC's vectors in `tests/test_poly1305.py`; do not trust this
transcription by reading it.
"""

from __future__ import annotations

__all__ = ["poly1305_mac"]

_P = (1 << 130) - 5
#: §2.5: the bits of r that must be cleared before it is used as the evaluation point.
_R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305_mac(key: bytes, message: bytes) -> bytes:
    """The 16-byte tag over `message` under a 32-byte one-time key (r ‖ s)."""
    if len(key) != 32:
        raise ValueError("poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & _R_CLAMP
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(message), 16):
        chunk = message[i:i + 16]
        # Each block is read as a little-endian number with a 1 bit appended above its
        # highest byte -- for a full block that is 2^128, for a short final block it sits
        # right after the data. That bit is what makes the length part of the tag.
        n = int.from_bytes(chunk, "little") | (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % _P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")
