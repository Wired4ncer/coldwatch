"""Persistence: the §3 schema in SQLite, keyed hashes and AEAD ciphertexts at rest.

`Store` is both the enrolment layer's record and the matching loop's `WatchIndex`. See
`store.py` for what can and cannot be read back out of it.

⚠️ There is no event-history table and there must not be one. A stored "item N fired at
14:32:07" row is a timing side channel that reverses the HMAC anonymity when matched against
public chain data. See CONTRIBUTING.md invariant I3 and docs/architecture.md §3.
"""

from coldwatch.storage.store import (
    TOKEN_BYTES,
    ChannelRow,
    Item,
    ItemStatus,
    NotActivatable,
    NotArmable,
    Store,
    UnknownRow,
    Watch,
    WatchStatus,
)

__all__ = [
    "TOKEN_BYTES",
    "ChannelRow",
    "Item",
    "ItemStatus",
    "NotActivatable",
    "NotArmable",
    "Store",
    "UnknownRow",
    "Watch",
    "WatchStatus",
]
