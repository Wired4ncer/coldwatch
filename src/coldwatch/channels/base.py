"""The delivery-channel contract.

This is the seam the whole delivery side is built on: a channel implementation can be written
and tested against these types alone — no node, no database, no network.

The privacy analysis is encoded here as *types* rather than left to review, so the enrolment UI
can rank channels honestly and a renderer cannot over-share by accident. See CONTRIBUTING.md §1
for the invariants; the important one here is **I2**, and it is enforced by `Alert` simply not
carrying the fields it forbids.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import ClassVar, Protocol, runtime_checkable

__all__ = [
    "Alert",
    "AlertKind",
    "Channel",
    "DeliveryResult",
    "Direction",
    "PrivacyClass",
]


class PrivacyClass(Enum):
    """How much the operator and any intermediary can see.

    Shown to the user at enrolment. Ranking a channel honestly is part of the product, not a
    nicety — someone choosing email should know what that costs them.
    """

    E2E_PRIVATE = "e2e"
    """Content *and* metadata sealed. Nostr NIP-17 gift-wrap."""

    ENDPOINT_TRUSTED = "endpoint"
    """The user controls the endpoint: webhook, self-hosted ntfy."""

    PROVIDER_READS = "provider"
    """Operator and provider can read content and metadata: email, public ntfy.

    Requires an explicit acknowledgement from the user before the channel can be used.
    """


class Direction(Enum):
    OUTGOING = "outgoing"
    """Funds left a watched address. Always an alarm, always sent immediately."""

    INCOMING = "incoming"
    """Funds arrived. Informational by default — a deposit is not an emergency, and
    treating it as one trains the user to ignore the alarm that matters."""


class AlertKind(Enum):
    MOVEMENT = "movement"
    TEST_FIRE = "test_fire"
    """Sent at setup. A channel is not considered working until the user confirms receipt."""
    LOW_BALANCE = "low_balance"
    WATCH_STOPPED = "watch_stopped"
    """Never fail silently: stopping is announced explicitly (invariant I5)."""
    HEARTBEAT = "heartbeat"
    """Optional "all quiet" digest. Also doubles as cover traffic."""


@dataclass(frozen=True)
class Alert:
    """Everything a renderer is allowed to know.

    ⚠️ **Do not add fields to this class.** No address, no amount, no transaction id, no block
    height. A renderer physically cannot leak what it never receives, which is what makes
    invariant I2 a property of the code rather than a promise about review habits.

    If a template seems to need something this does not carry, that is the invariant working.
    Open an issue rather than adding the field — see `tests/test_channels.py`, which fails if
    this class grows.
    """

    kind: AlertKind
    label: str
    """The user's own nickname for the watch. The only user-supplied data in any alert."""
    chain: str
    direction: Direction | None
    """None for alerts that are not about a movement (balance notices, heartbeats)."""
    fired_at: datetime


@dataclass(frozen=True)
class DeliveryResult:
    ok: bool
    retriable: bool
    """Whether a failure is worth retrying. A permanent failure must not be retried forever —
    an alarm that exhausts every channel is itself an event the watchdog needs to see."""
    detail: str = ""
    """Short diagnostic for logs. ⚠️ **Never** include the destination or the alert content:
    this string is logged, and the destination is exactly what must not be."""


@runtime_checkable
class Channel(Protocol):
    """One delivery mechanism.

    Implementations live in `coldwatch.channels`. They are pure: given a destination and an
    `Alert`, deliver it and report what happened. No database access, no key handling — the
    caller decrypts the destination just-in-time and drops it.
    """

    kind: ClassVar[str]
    privacy_class: ClassVar[PrivacyClass]

    def validate_dest(self, raw: str) -> str:
        """Normalise and validate a destination at enrolment time.

        Returns the canonical form to be encrypted at rest. Raises `ValueError` on anything
        malformed — enrolment should fail loudly rather than store a destination that will
        turn out to be undeliverable at 3am.
        """
        ...

    def send(self, dest: str, alert: Alert) -> DeliveryResult:
        """Deliver one alert.

        `dest` is plaintext and short-lived: it is decrypted by the caller, used here, and
        dropped. It must not be logged, stored, or placed in `DeliveryResult.detail`.
        """
        ...
