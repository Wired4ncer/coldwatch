"""NIP-01 event identity: canonical id serialization and BIP340 Schnorr signing/verification.

`coincurve` is the one dependency this whole package needed to add (see SECURITY.md): Schnorr
signing over secp256k1 and its x-only pubkeys are exactly the elliptic-curve arithmetic this
project doesn't hand-roll, unlike `chacha20.py` or `bech32.py`.

`event_id`'s serialization is verified in `tests/test_nip01.py` against real events from 59.md's
own worked example (extracted programmatically from the spec text, not hand-copied — a
transcription error here would silently produce IDs incompatible with every other client), and
`verify_event_sig` is checked against a signature that module actually produced with
nostr-tools, proving this reads what other implementations write, not just what it writes itself.
"""

from __future__ import annotations

import hashlib
import json
import secrets

from coincurve import PrivateKey, PublicKeyXOnly

__all__ = ["event_id", "pubkey_hex_from_privkey", "sign_event_id", "verify_event_sig"]


def _serialize_for_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    # NIP-01: compact JSON, UTF-8, no extra whitespace. json.dumps with ensure_ascii=False keeps
    # non-ASCII content literal (also required); Python's default control-character escaping
    # already matches the spec's required \n \" \\ \r \t \b \f shorthands.
    array = [0, pubkey_hex, created_at, kind, tags, content]
    return json.dumps(array, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def event_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> str:
    return hashlib.sha256(_serialize_for_id(pubkey_hex, created_at, kind, tags, content)).hexdigest()


def pubkey_hex_from_privkey(privkey_hex: str) -> str:
    secret = PrivateKey(bytes.fromhex(privkey_hex))
    return PublicKeyXOnly.from_valid_secret(secret.secret).format().hex()


def sign_event_id(privkey_hex: str, event_id_hex: str) -> str:
    secret = PrivateKey(bytes.fromhex(privkey_hex))
    digest = bytes.fromhex(event_id_hex)
    return secret.sign_schnorr(digest, aux_randomness=secrets.token_bytes(32)).hex()


def verify_event_sig(pubkey_hex: str, event_id_hex: str, sig_hex: str) -> bool:
    try:
        xonly = PublicKeyXOnly(bytes.fromhex(pubkey_hex))
        return xonly.verify(bytes.fromhex(sig_hex), bytes.fromhex(event_id_hex))
    except ValueError:
        return False
