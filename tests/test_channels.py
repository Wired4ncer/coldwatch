"""Contract tests for the delivery-channel seam.

Most of these exist to make the privacy invariants *executable*. A rule that lives only in
CONTRIBUTING.md is enforced by whoever happens to review the pull request; a rule with a test
is enforced by CI at 3am when nobody is looking.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from coldwatch.channels import (
    Alert,
    AlertKind,
    Channel,
    DeliveryResult,
    Direction,
    PrivacyClass,
)


def make_alert(**overrides) -> Alert:
    base = {
        "kind": AlertKind.MOVEMENT,
        "label": "cold-1",
        "chain": "btc",
        "direction": Direction.OUTGOING,
        "fired_at": datetime(2026, 8, 6, tzinfo=UTC),
    }
    base.update(overrides)
    return Alert(**base)


# ── invariant I2: an alert carries a nickname, a chain and a status. Nothing else. ──────────

#: The complete set of fields an Alert may ever have. Adding to this is a design decision,
#: not a refactor — it must be argued in an issue, because every field here is something a
#: renderer can leak.
ALLOWED_ALERT_FIELDS = {"kind", "label", "chain", "direction", "fired_at"}

#: Anything resembling these must never appear. Listed explicitly so the failure message
#: names the actual problem rather than just a set difference.
FORBIDDEN_SUBSTRINGS = (
    "address", "addr", "amount", "value", "sats", "satoshi",
    "txid", "tx_id", "transaction", "outpoint", "script", "spk",
    "height", "block", "fee", "balance",
)


def test_alert_carries_nothing_beyond_the_allowed_fields():
    """Invariant I2, enforced. If this fails, an Alert grew a field.

    That is not necessarily wrong — but it is a privacy decision, and it must be made
    deliberately in an issue rather than arrived at while writing a template.
    """
    actual = {f.name for f in dataclasses.fields(Alert)}
    assert actual == ALLOWED_ALERT_FIELDS, (
        f"Alert's fields changed: added {actual - ALLOWED_ALERT_FIELDS or '{}'}, "
        f"removed {ALLOWED_ALERT_FIELDS - actual or '{}'}. "
        "See CONTRIBUTING.md invariant I2 before updating this test."
    )


def test_no_alert_field_looks_like_chain_data():
    """Catches the specific mistake of adding an address or amount 'just for context'."""
    for field in dataclasses.fields(Alert):
        lowered = field.name.lower()
        for bad in FORBIDDEN_SUBSTRINGS:
            assert bad not in lowered, (
                f"Alert.{field.name} looks like chain data ({bad!r}). An alert may not carry "
                "the address, amount, txid or anything derived from them — invariant I2."
            )


def test_alert_is_immutable():
    """Frozen so a renderer cannot mutate an alert on its way out."""
    alert = make_alert()
    with pytest.raises(dataclasses.FrozenInstanceError):
        alert.label = "something else"  # type: ignore[misc]


def test_alert_allows_no_direction_for_non_movement_kinds():
    """Balance notices and heartbeats are not about a movement."""
    alert = make_alert(kind=AlertKind.LOW_BALANCE, direction=None)
    assert alert.direction is None


# ── the Channel protocol ────────────────────────────────────────────────────────────────────


class _StubChannel:
    """A minimal conforming implementation — proof the protocol is satisfiable as written."""

    kind = "stub"
    privacy_class = PrivacyClass.ENDPOINT_TRUSTED

    def __init__(self) -> None:
        self.sent: list[tuple[str, Alert]] = []

    def validate_dest(self, raw: str) -> str:
        if not raw.strip():
            raise ValueError("empty destination")
        return raw.strip().lower()

    def send(self, dest: str, alert: Alert) -> DeliveryResult:
        self.sent.append((dest, alert))
        return DeliveryResult(ok=True, retriable=False)


def test_stub_satisfies_the_channel_protocol():
    assert isinstance(_StubChannel(), Channel)


def test_validate_dest_rejects_junk_rather_than_storing_it():
    """Enrolment should fail loudly. A destination that turns out to be undeliverable is
    only discovered at 3am, which is precisely the wrong time."""
    with pytest.raises(ValueError):
        _StubChannel().validate_dest("   ")


def test_delivery_result_detail_defaults_empty():
    """`detail` is logged. The default must be empty rather than something incidental."""
    assert DeliveryResult(ok=False, retriable=True).detail == ""


# ── privacy classes ─────────────────────────────────────────────────────────────────────────


def test_every_privacy_class_is_distinct_and_named():
    values = [p.value for p in PrivacyClass]
    assert len(values) == len(set(values))
    assert set(values) == {"e2e", "endpoint", "provider"}
