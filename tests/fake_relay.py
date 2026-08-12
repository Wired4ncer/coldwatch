"""An in-process stand-in for the relay connection `NostrChannel` talks to, for testing without
a real relay or a WebSocket. Mirrors `fake_smtp.py`: the WebSocket wire protocol is
websocket-client's job, already exercised by its own test suite. What is worth checking is
`NostrChannel`'s own logic -- how an `OK`/`CLOSED` reply turns into a `DeliveryResult`, and that
a connection failure never leaks the destination or the alert content into it.
"""

from __future__ import annotations

import json
from typing import Self

__all__ = ["FakeRelay"]


class FakeRelay:
    """Programmable stand-in for one connected relay. Injected via
    `NostrChannel(..., connect=lambda relay, timeout: relays_by_url[relay])`.
    """

    def __init__(
        self,
        *,
        ok: bool = True,
        note: str = "",
        recv_error: Exception | None = None,
    ) -> None:
        self.ok = ok
        self.note = note
        self.recv_error = recv_error
        self.sent: list[dict] = []
        self.closed = False

    def send(self, text: str) -> None:
        frame = json.loads(text)
        assert frame[0] == "EVENT"
        self.sent.append(frame[1])

    def recv(self) -> str:
        if self.recv_error is not None:
            raise self.recv_error
        event_id = self.sent[-1]["id"]
        return json.dumps(["OK", event_id, self.ok, self.note])

    def close(self) -> None:
        self.closed = True


class RaisingConnect:
    """A `connect` callable that raises instead of returning a connection -- for a relay that's
    unreachable outright (DNS failure, connection refused, TLS handshake failure, ...)."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def __call__(self, relay: str, timeout: float) -> Self:
        raise self.error


def make_connect(relays: dict[str, object]):
    """Build a `connect(relay, timeout)` that dispatches to a `FakeRelay` or `RaisingConnect`
    per relay URL, so multi-relay fallback can be tested without a real network."""

    def connect(relay: str, timeout: float):
        target = relays[relay]
        if isinstance(target, RaisingConnect):
            return target(relay, timeout)
        return target

    return connect
