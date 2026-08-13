"""NIP-59 gift wrap over a NIP-17 kind:14 chat message: rumor → seal → wrap.

Three layers, each hiding what the last one exposed (see 59.md's overview):

- The **rumor** (kind 14) carries the actual alert text. It is never signed, so a leaked rumor
  proves nothing — deniability, not that coldwatch relies on it.
- The **seal** (kind 13) encrypts the rumor to the recipient and is signed with the service's
  real, persistent key — this is `NostrChannel`'s "single published npub" trust anchor from
  issue #3: the recipient's client can show "this seal was really signed by coldwatch."
- The **wrap** (kind 1059) encrypts the seal to the recipient again, this time signed by a
  fresh, single-use ephemeral key generated per message and discarded immediately after. This
  is what a relay actually sees: a random pubkey nobody can link across messages, sending an
  opaque blob to one `p`-tagged recipient. The service's real key never touches the wire.

`created_at` on both the seal and the wrap is independently randomized up to two days into the
past, per 59.md/17.md, so grouping by timestamp doesn't correlate messages.

Verified in `tests/test_giftwrap.py` by decrypting 59.md's own worked example — a gift wrap that
another implementation (nostr-tools) produced — and recovering the exact rumor.
"""

from __future__ import annotations

import json
import secrets
import time

from coldwatch.channels.nostr import nip01, nip44

__all__ = ["make_rumor", "make_seal", "make_wrap"]

_TWO_DAYS_SECONDS = 2 * 24 * 60 * 60


def _random_past_timestamp() -> int:
    return int(time.time()) - secrets.randbelow(_TWO_DAYS_SECONDS + 1)


def _canonical_event_json(event: dict) -> str:
    # Key order matches the wire examples in 59.md/17.md; JSON semantics don't care, but a
    # stable order makes this reproducible to read in logs/tests.
    ordered = {
        "id": event["id"],
        "pubkey": event["pubkey"],
        "created_at": event["created_at"],
        "kind": event["kind"],
        "tags": event["tags"],
        "content": event["content"],
    }
    if "sig" in event:
        ordered["sig"] = event["sig"]
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def make_rumor(
    sender_privkey_hex: str, recipient_pubkey_hex: str, content: str, *, kind: int = 14
) -> dict:
    """An unsigned kind:14 chat message (NIP-17). `id` is computed; there is no `sig`."""
    pubkey = nip01.pubkey_hex_from_privkey(sender_privkey_hex)
    created_at = int(time.time())
    tags = [["p", recipient_pubkey_hex]]
    rid = nip01.event_id(pubkey, created_at, kind, tags, content)
    return {
        "id": rid, "pubkey": pubkey, "created_at": created_at, "kind": kind,
        "tags": tags, "content": content,
    }


def make_seal(rumor: dict, sender_privkey_hex: str, recipient_pubkey_hex: str) -> dict:
    """Encrypt the rumor to the recipient, signed by the sender's real key. Tags always empty."""
    conversation_key = nip44.get_conversation_key(sender_privkey_hex, recipient_pubkey_hex)
    content = nip44.encrypt(_canonical_event_json(rumor), conversation_key, secrets.token_bytes(32))
    pubkey = nip01.pubkey_hex_from_privkey(sender_privkey_hex)
    created_at = _random_past_timestamp()
    seal_id = nip01.event_id(pubkey, created_at, 13, [], content)
    sig = nip01.sign_event_id(sender_privkey_hex, seal_id)
    return {
        "id": seal_id, "pubkey": pubkey, "created_at": created_at, "kind": 13,
        "tags": [], "content": content, "sig": sig,
    }


def make_wrap(seal: dict, recipient_pubkey_hex: str) -> dict:
    """Encrypt the seal to the recipient under a fresh one-time key, then forget that key."""
    ephemeral_privkey_hex = secrets.token_bytes(32).hex()
    conversation_key = nip44.get_conversation_key(ephemeral_privkey_hex, recipient_pubkey_hex)
    content = nip44.encrypt(_canonical_event_json(seal), conversation_key, secrets.token_bytes(32))
    pubkey = nip01.pubkey_hex_from_privkey(ephemeral_privkey_hex)
    created_at = _random_past_timestamp()
    tags = [["p", recipient_pubkey_hex]]
    wrap_id = nip01.event_id(pubkey, created_at, 1059, tags, content)
    sig = nip01.sign_event_id(ephemeral_privkey_hex, wrap_id)
    return {
        "id": wrap_id, "pubkey": pubkey, "created_at": created_at, "kind": 1059,
        "tags": tags, "content": content, "sig": sig,
    }
