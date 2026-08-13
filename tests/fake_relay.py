"""An in-process stand-in for the relay connection `NostrChannel` talks to, for testing without
a real relay or a WebSocket. Mirrors `fake_smtp.py`: the WebSocket wire protocol is
websocket-client's job, already exercised by its own test suite. What is worth checking is
`NostrChannel`'s own logic -- how an `OK`/`CLOSED` reply turns into a `DeliveryResult`, and that
a connection failure never leaks the destination or the alert content into it.

Two doubles, and the difference between them is the point. `FakeRelay` is the well-behaved
relay: it can only ever produce `["OK", <id>, <bool>, <str>]`, which is the shape the channel
handles correctly and therefore the shape that hides every way it does not. `ScriptedRelay`
hands the raw frame to the test instead, because a relay is infrastructure we don't run: its
*content* is already treated as hostile (see `_classify_note`), and its *shape* deserves the
same suspicion.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from typing import Self

import websocket

__all__ = [
    "FakeRelay",
    "RaisingConnect",
    "ScriptedRelay",
    "closed_frame",
    "make_connect",
    "ok_frame",
]


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


#: A frame is either raw text sent verbatim, or a callable handed the id of the event just
#: published -- the only part of a reply a test cannot know in advance.
Frame = str | Callable[[str], str]


class ScriptedRelay:
    """A relay that replies with a fixed script of *raw* frames, byte for byte.

    Unlike `FakeRelay`, nothing here serialises a well-formed reply on the test's behalf, so a
    test can produce what a real relay can: a connection closed without an OK (websocket-client
    returns `""` for a CLOSE opcode), a frame that isn't JSON at all, an `OK` whose flag or
    message is the wrong JSON type, a `CLOSED`, or a relay that just keeps talking.

    The script is finite on purpose. When it runs out `recv` raises -- by default the same
    `WebSocketTimeoutException` a real socket raises once a relay goes quiet -- so a test can
    assert that `send` stopped reading early, and no test can hang if it doesn't.
    """

    def __init__(
        self,
        frames: Sequence[Frame],
        *,
        exhausted: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.frames = list(frames)
        self.exhausted = exhausted or websocket.WebSocketTimeoutException("the relay went quiet")
        #: Seconds each `recv` takes. Zero for every test that only cares about content; a real
        #: value for the ones that care about *elapsed time*, since an in-process double
        #: otherwise returns thousands of frames without the wall clock moving at all -- and a
        #: deadline is measured in seconds, not in frames.
        self.delay = delay
        self.sent: list[dict] = []
        self.recv_calls = 0
        self.closed = False

    def send(self, text: str) -> None:
        frame = json.loads(text)
        assert frame[0] == "EVENT"
        self.sent.append(frame[1])

    def recv(self) -> str:
        if self.delay:
            time.sleep(self.delay)
        self.recv_calls += 1
        if self.recv_calls > len(self.frames):
            raise self.exhausted
        frame = self.frames[self.recv_calls - 1]
        return frame(self.sent[-1]["id"]) if callable(frame) else frame

    def close(self) -> None:
        self.closed = True


def ok_frame(accepted: object = True, note: object = "") -> Frame:
    """An `OK` for the event just published. `accepted` and `note` are deliberately untyped:
    NIP-01 says bool and string, and the point of this helper is to be able to send what a
    relay that disagrees would send."""
    return lambda event_id: json.dumps(["OK", event_id, accepted, note])


def closed_frame(subscription_id: str = "sub-1", message: str = "error: shutting down") -> Frame:
    """A NIP-01 `CLOSED`. Note the id is a *subscription* id -- there is no event id in this
    message, which is the whole reason it needs its own frame builder."""
    return json.dumps(["CLOSED", subscription_id, message])


class RaisingConnect:
    """A `connect` callable that raises instead of returning a connection -- for a relay that's
    unreachable outright (DNS failure, connection refused, TLS handshake failure, ...)."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def __call__(self, relay: str, timeout: float) -> Self:
        raise self.error


def make_connect(relays: dict[str, object]):
    """Build a `connect(relay, timeout)` that dispatches to a `FakeRelay`, a `ScriptedRelay` or
    a `RaisingConnect` per relay URL, so multi-relay fallback can be tested without a real
    network."""

    def connect(relay: str, timeout: float):
        target = relays[relay]
        if isinstance(target, RaisingConnect):
            return target(relay, timeout)
        return target

    return connect
