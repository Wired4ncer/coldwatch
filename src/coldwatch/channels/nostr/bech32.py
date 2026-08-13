"""BIP-173 bech32 (not bech32m) — just enough to encode/decode `npub1...` (NIP-19).

Stdlib-only: this is an encoding, not a cryptographic primitive (no secret-dependent branching,
nothing to get subtly wrong in a way that leaks a key), so it doesn't need `coincurve` the way
signing and ECDH do. See `nip44.py`'s module docstring for where the line is drawn.
"""

from __future__ import annotations

__all__ = ["decode_npub", "encode_npub"]

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GENERATOR[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _verify_checksum(hrp: str, data: list[int]) -> bool:
    return _polymod(_hrp_expand(hrp) + data) == 1


def _convertbits(data: bytes, frombits: int, tobits: int, *, pad: bool) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(_CHARSET[d] for d in combined)


def _bech32_decode(s: str) -> tuple[str, list[int]]:
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        raise ValueError("invalid bech32 character")
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed-case bech32 string")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("no bech32 separator")
    hrp = s[:pos]
    try:
        data = [_CHARSET.index(c) for c in s[pos + 1:]]
    except ValueError:
        raise ValueError("invalid bech32 data character") from None
    if not _verify_checksum(hrp, data):
        raise ValueError("invalid bech32 checksum")
    return hrp, data[:-6]


def encode_npub(pubkey: bytes) -> str:
    if len(pubkey) != 32:
        raise ValueError("pubkey must be 32 bytes")
    words = _convertbits(pubkey, 8, 5, pad=True)
    assert words is not None
    return _bech32_encode("npub", words)


def decode_npub(npub: str) -> bytes:
    hrp, data = _bech32_decode(npub)
    if hrp != "npub":
        raise ValueError("not an npub")
    decoded = _convertbits(bytes(data), 5, 8, pad=False)
    if decoded is None or len(decoded) != 32:
        raise ValueError("npub does not decode to a 32-byte key")
    return bytes(decoded)
