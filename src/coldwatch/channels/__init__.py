"""Delivery channels.

`base` defines the contract; each concrete channel is its own module. A channel is
implementable and testable with no node, no database and no network — that is deliberate,
so this work can proceed independently of the ingest side.

Implemented: none yet. Email (#2) and Nostr (#3) are the first two.
"""

from coldwatch.channels.base import (
    Alert,
    AlertKind,
    Channel,
    DeliveryResult,
    Direction,
    PrivacyClass,
)

__all__ = [
    "Alert",
    "AlertKind",
    "Channel",
    "DeliveryResult",
    "Direction",
    "PrivacyClass",
]
