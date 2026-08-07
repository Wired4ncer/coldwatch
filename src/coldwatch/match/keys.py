"""Key derivation and the keyed hashes the matching loop compares.

The whole privacy story rests on one property: **an attacker holding the database cannot
match it against the chain.** Addresses come from a public, enumerable set, so a plain hash
buys nothing — anyone can hash every address in existence and look for collisions. The key is
what makes the stored form unmatchable. See docs/architecture.md §1.

Two subkeys, because their exposure profiles differ: ``k_match`` is needed constantly in the
hot loop, ``k_store`` only at enrolment, alert-fire and dashboard render.

Stdlib only, deliberately. HKDF is thirty lines and the project has no runtime dependencies;
adding one for this would be a supply-chain surface in exchange for nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

__all__ = [
    "MIN_MASTER_BYTES",
    "Subkeys",
    "canonical_outpoint",
    "derive_subkeys",
    "hkdf",
    "outpoint_hmac",
    "spk_hmac",
    "txid_from_display",
    "txid_to_display",
]

HASH_LEN = 32

#: HKDF info strings. Versioned: changing a derivation without changing the string would
#: silently invalidate every stored HMAC, and the failure mode is "nothing ever matches
#: again", which looks exactly like a quiet service rather than a broken one.
INFO_MATCH = b"coldwatch/match/v1"
INFO_STORE = b"coldwatch/store/v1"

#: Domain-separation tags. Without these, an scriptPubKey and a canonically serialised
#: outpoint are both just byte strings under the same key, and a 36-byte script could in
#: principle collide with an outpoint. Cheap to prevent, tedious to debug.
TAG_SPK = b"spk"
TAG_OUTPOINT = b"outpoint"

#: Shorter than this is not a key. Enforced here rather than at the call site because there
#: is exactly one place to get this wrong and it should fail at startup, not at 3am.
MIN_MASTER_BYTES = 16


@dataclass(frozen=True)
class Subkeys:
    """The two derived keys. The master itself is not retained — nothing needs it again."""

    match: bytes
    """Keyed HMAC for watch targets. Hot path."""
    store: bytes
    """AEAD key for labels and channel destinations. Not used by the matching loop."""


def hkdf(ikm: bytes, info: bytes, salt: bytes = b"", length: int = HASH_LEN) -> bytes:
    """HKDF-SHA256 (RFC 5869): extract-then-expand.

    ``salt`` defaults to empty, which RFC 5869 defines as ``HashLen`` zero bytes. That is the
    documented no-salt case, not an oversight — the master secret is already high-entropy, so
    the salt adds nothing here.
    """
    if length < 1 or length > 255 * HASH_LEN:
        raise ValueError("length out of range for HKDF-SHA256")
    prk = hmac.new(salt or bytes(HASH_LEN), ikm, hashlib.sha256).digest()
    out, block = b"", b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_subkeys(master: bytes) -> Subkeys:
    """Derive both subkeys from the master secret.

    The master lives outside the database — environment variable or systemd
    ``LoadCredential`` — and never on the same backup media as the database. A backup holding
    both is a backup holding the plaintext.
    """
    if len(master) < MIN_MASTER_BYTES:
        # Deliberately does not include the value or its length in the message: this string
        # ends up in logs, and "the master key is 8 bytes" is a useful hint to an attacker.
        raise ValueError("master secret too short")
    return Subkeys(
        match=hkdf(master, INFO_MATCH),
        store=hkdf(master, INFO_STORE),
    )


def _tagged(key: bytes, tag: bytes, payload: bytes) -> bytes:
    return hmac.new(key, tag + b"\x00" + payload, hashlib.sha256).digest()


def spk_hmac(k_match: bytes, spk: bytes) -> bytes:
    """Keyed hash of a scriptPubKey.

    HMAC the script, never the address string. The script is the canonical form — it kills
    encoding aliases (a P2WPKH output has one script but several valid address spellings), and
    it is what the stream hands us anyway, so no conversion has to happen in the hot loop.
    """
    return _tagged(k_match, TAG_SPK, spk)


def canonical_outpoint(txid: bytes, vout: int) -> bytes:
    """Serialise an outpoint the way a transaction input does: txid ‖ vout, both little-endian.

    ⚠️ ``txid`` is in **internal** byte order — the order the bytes appear in a raw
    transaction — not the reversed display order shown by block explorers and returned by
    bitcoind's JSON-RPC. Mixing the two is the classic Bitcoin byte-order bug, and here it
    fails in the worst possible way: enrolment stores one orientation, the matching loop
    computes the other, nothing ever matches, and the service looks healthy while watching
    nothing. Use :func:`txid_from_display` at every RPC boundary.
    """
    if len(txid) != 32:
        raise ValueError("txid must be 32 bytes")
    if not 0 <= vout <= 0xFFFFFFFF:
        raise ValueError("vout out of range")
    return txid + struct.pack("<I", vout)


def outpoint_hmac(k_match: bytes, txid: bytes, vout: int) -> bytes:
    """Keyed hash of an outpoint, for spend detection against the live UTXO set."""
    return _tagged(k_match, TAG_OUTPOINT, canonical_outpoint(txid, vout))


def txid_from_display(display_hex: str) -> bytes:
    """Convert an RPC/explorer txid string to internal byte order.

    Every txid arriving as text — ``scantxoutset`` results, ``getblock`` output, anything a
    human pasted — goes through here before it touches :func:`canonical_outpoint`.
    """
    raw = bytes.fromhex(display_hex)
    if len(raw) != 32:
        raise ValueError("txid must be 32 bytes")
    return raw[::-1]


def txid_to_display(txid: bytes) -> str:
    """Inverse of :func:`txid_from_display`, for RPC calls that take a txid as text.

    Not for logging. A txid identifies a watched address the moment it is correlated with the
    public chain, so it belongs in an RPC argument and nowhere else.
    """
    if len(txid) != 32:
        raise ValueError("txid must be 32 bytes")
    return txid[::-1].hex()
