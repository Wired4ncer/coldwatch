"""Delivery channels.

`base` defines the contract; each concrete channel is its own module. A channel is
implementable and testable with no node, no database and no network — that is deliberate,
so this work can proceed independently of the ingest side.

Implemented: email (#2). Nostr (#3) is next.
"""

from coldwatch.channels.base import (
    Alert,
    AlertKind,
    Channel,
    DeliveryResult,
    Direction,
    PrivacyClass,
)
from coldwatch.channels.email import EmailChannel, MissingConfig

__all__ = [
    "Alert",
    "AlertKind",
    "Channel",
    "DeliveryResult",
    "Direction",
    "EmailChannel",
    "MissingConfig",
    "PrivacyClass",
]
