"""Delivery channels.

`base` defines the contract; each concrete channel is its own module (or, for Nostr, its own
subpackage — see `nostr/__init__.py`). A channel is implementable and testable with no node,
no database and no network — that is deliberate, so this work can proceed independently of the
ingest side.

Implemented: email (#2), Nostr (#3).
"""

from coldwatch.channels.base import (
    Alert,
    AlertKind,
    Channel,
    DeliveryResult,
    Direction,
    PrivacyClass,
)
from coldwatch.channels.email import EmailChannel
from coldwatch.channels.email import MissingConfig as EmailMissingConfig
from coldwatch.channels.nostr import MissingConfig as NostrMissingConfig
from coldwatch.channels.nostr import NostrChannel

__all__ = [
    "Alert",
    "AlertKind",
    "Channel",
    "DeliveryResult",
    "Direction",
    "EmailChannel",
    "EmailMissingConfig",
    "NostrChannel",
    "NostrMissingConfig",
    "PrivacyClass",
]
