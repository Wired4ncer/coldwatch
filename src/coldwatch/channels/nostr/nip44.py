"""NIP-44 v2 encrypted payloads: secp256k1 ECDH, HKDF, padding, ChaCha20, HMAC-SHA256, base64.

This is what makes the gift wrap in `giftwrap.py` actually opaque: everything downstream of
`get_conversation_key` here is stdlib (`chacha20.py`, `hmac`, `hashlib`, `base64`) — the one
place this module reaches for `coincurve` is the ECDH scalar multiplication itself, which is
exactly the kind of elliptic-curve arithmetic this project doesn't hand-roll (see SECURITY.md).

`get_conversation_key` deliberately does **not** use `coincurve.PrivateKey.ecdh()`: that method
returns `sha256(compressed_shared_point)` (to prevent malleability, per its docstring), but
NIP-44 requires the raw, unhashed 32-byte x-coordinate of the shared point — it does its own
HKDF over that raw value. Using the hashed variant here would silently produce a conversation
key incompatible with every other NIP-44 implementation. See 44.md §"Details" for the warning
("NIP44 doesn't do hashing of the output... some libraries hash it").

Verified byte-for-byte against the official test vectors (`tests/fixtures/nip44.vectors.json`,
from https://github.com/paulmillr/nip44) in `tests/test_nip44.py`, including the "invalid"
sections (bad conversation keys, truncated payloads, bad MACs, bad padding).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math

from coincurve import PrivateKey, PublicKey

from coldwatch.channels.nostr.chacha20 import chacha20_xor

__all__ = ["decrypt", "encrypt", "get_conversation_key"]

_VERSION = 2
_MIN_PAYLOAD_CHARS = 132
_MIN_DECODED_BYTES = 99
_EXTENDED_PREFIX_THRESHOLD = 65536
_MAX_PLAINTEXT_SIZE = 0xFFFFFFFF


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def get_conversation_key(privkey_hex: str, pubkey_hex: str) -> bytes:
    """Symmetric in its two keys: `get_conversation_key(a, B) == get_conversation_key(b, A)`."""
    privkey = PrivateKey(bytes.fromhex(privkey_hex))
    # BIP340 x-only pubkeys assume even-y on reconstruction — hence the 0x02 prefix, per 44.md.
    point_b = PublicKey(b"\x02" + bytes.fromhex(pubkey_hex))
    shared_point = point_b.multiply(privkey.secret)
    shared_x = shared_point.format(compressed=True)[1:33]
    return _hkdf_extract(salt=b"nip44-v2", ikm=shared_x)


def _get_message_keys(conversation_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    if len(conversation_key) != 32:
        raise ValueError("invalid conversation_key length")
    if len(nonce) != 32:
        raise ValueError("invalid nonce length")
    keys = _hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


def _calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (((unpadded_len - 1) // chunk) + 1)


def _pad(plaintext: str) -> bytes:
    unpadded = plaintext.encode("utf-8")
    unpadded_len = len(unpadded)
    if unpadded_len < 1 or unpadded_len > _MAX_PLAINTEXT_SIZE:
        raise ValueError("invalid plaintext length")
    if unpadded_len >= _EXTENDED_PREFIX_THRESHOLD:
        prefix = b"\x00\x00" + unpadded_len.to_bytes(4, "big")
    else:
        prefix = unpadded_len.to_bytes(2, "big")
    suffix = b"\x00" * (_calc_padded_len(unpadded_len) - unpadded_len)
    return prefix + unpadded + suffix


def _unpad(padded: bytes) -> str:
    first_two = int.from_bytes(padded[0:2], "big")
    if first_two == 0:
        if len(padded) < 6:
            raise ValueError("invalid padding")
        unpadded_len = int.from_bytes(padded[2:6], "big")
        if unpadded_len < _EXTENDED_PREFIX_THRESHOLD:
            raise ValueError("invalid padding")
        prefix_len = 6
    else:
        unpadded_len = first_two
        prefix_len = 2
    unpadded = padded[prefix_len:prefix_len + unpadded_len]
    if (
        unpadded_len == 0
        or len(unpadded) != unpadded_len
        or len(padded) != prefix_len + _calc_padded_len(unpadded_len)
    ):
        raise ValueError("invalid padding")
    return unpadded.decode("utf-8")


def _hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    if len(aad) != 32:
        raise ValueError("AAD must be 32 bytes")
    return hmac.new(key, aad + message, hashlib.sha256).digest()


def encrypt(plaintext: str, conversation_key: bytes, nonce: bytes) -> str:
    chacha_key, chacha_nonce, hmac_key = _get_message_keys(conversation_key, nonce)
    padded = _pad(plaintext)
    ciphertext = chacha20_xor(chacha_key, chacha_nonce, padded)
    mac = _hmac_aad(hmac_key, ciphertext, aad=nonce)
    return base64.b64encode(bytes([_VERSION]) + nonce + ciphertext + mac).decode()


def _decode_payload(payload: str) -> tuple[bytes, bytes, bytes]:
    if len(payload) == 0 or payload[0] == "#":
        raise ValueError("unsupported encryption version")
    if len(payload) < _MIN_PAYLOAD_CHARS:
        raise ValueError("invalid payload size")
    # binascii.Error (raised by validate=True on malformed input) is itself a ValueError
    # subclass, so a caller catching ValueError already catches this without a wrapper here.
    data = base64.b64decode(payload, validate=True)
    if len(data) < _MIN_DECODED_BYTES:
        raise ValueError("invalid data size")
    version = data[0]
    if version != _VERSION:
        raise ValueError(f"unsupported encryption version {version}")
    nonce = data[1:33]
    ciphertext = data[33:len(data) - 32]
    mac = data[len(data) - 32:]
    return nonce, ciphertext, mac


def decrypt(payload: str, conversation_key: bytes) -> str:
    nonce, ciphertext, mac = _decode_payload(payload)
    chacha_key, chacha_nonce, hmac_key = _get_message_keys(conversation_key, nonce)
    calculated_mac = _hmac_aad(hmac_key, ciphertext, aad=nonce)
    if not hmac.compare_digest(calculated_mac, mac):
        raise ValueError("invalid MAC")
    padded_plaintext = chacha20_xor(chacha_key, chacha_nonce, ciphertext)
    return _unpad(padded_plaintext)
