"""Nostr delivery channel (issue #3) — NIP-17 gift-wrapped DM, the privacy-recommended rail.

Unlike email (`channels/email.py`), this channel cannot stay stdlib-only: NIP-44 needs
secp256k1 ECDH and BIP340 Schnorr signing, and there is no such thing as "roll your own"
elliptic-curve arithmetic here — that's what `coincurve` is for (see SECURITY.md). Relay
transport needs a WebSocket client, which is what `websocket-client` is for; that one is a
transport dependency, not a cryptographic one, so this module still doesn't hand-roll TLS or
frame parsing itself.

The service has **one** persistent identity (`self._pubkey`, derived from the configured
private key) — that's the seal's signer, and the "single published npub" trust anchor issue #3
asks for: a recipient's client can show "this was really signed by coldwatch." The wrap layer
still uses a fresh, single-use key per message (`giftwrap.make_wrap`), because that's what
actually keeps a relay from linking two alerts to the same sender — see `giftwrap.py`.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import ClassVar, Protocol

import websocket
from coincurve import PublicKey

from coldwatch.channels.base import Alert, AlertKind, DeliveryResult, Direction, PrivacyClass
from coldwatch.channels.nostr import bech32, giftwrap, nip01

__all__ = ["MissingConfig", "NostrChannel"]

DEFAULT_TIMEOUT = 15.0

ENV_PRIVKEY = "COLDWATCH_NOSTR_PRIVKEY"
ENV_PRIVKEY_FILE = "COLDWATCH_NOSTR_PRIVKEY_FILE"
#: Whitespace- or comma-separated wss:// relay URLs. See `NostrChannel.__init__` for why
#: ws:// (no TLS) is rejected outright rather than merely discouraged.
ENV_RELAYS = "COLDWATCH_NOSTR_RELAYS"

#: Mirrors email.py's credential precedence — see that module for the full reasoning on why
#: systemd's LoadCredential beats a bare environment variable.
ENV_SYSTEMD_CREDENTIALS = "CREDENTIALS_DIRECTORY"
SYSTEMD_CREDENTIAL_NAME = "nostr-privkey"

#: The machine-readable prefixes NIP-01 defines for a relay's OK/CLOSED message. Only these are
#: ever allowed into DeliveryResult.detail -- a relay's free-text human message is attacker-
#: controlled (it comes from infrastructure we don't run) and must never reach a log verbatim,
#: the same discipline email.py applies to SMTPRecipientsRefused's payload.
_KNOWN_NOTE_PREFIXES = frozenset(
    {"duplicate", "pow", "blocked", "rate-limited", "invalid", "restricted", "mute", "error"}
)
#: A relay rejecting for one of these reasons won't accept the same event on retry.
_PERMANENT_NOTE_PREFIXES = frozenset({"blocked", "invalid", "restricted"})


class MissingConfig(Exception):
    """A required setting was not found. Names the variable, never a value.

    See email.py's `MissingConfig`, which this mirrors.
    """


def _read_secret(path: Path) -> str:
    try:
        secret = path.read_text()
    except OSError as exc:
        raise MissingConfig(f"could not read {path}: {exc.strerror}") from None
    secret = secret.rstrip("\r\n")
    if not secret:
        raise MissingConfig(f"{path} is empty")
    return secret


def _read_privkey() -> str:
    credentials_dir = os.environ.get(ENV_SYSTEMD_CREDENTIALS)
    if credentials_dir:
        path = Path(credentials_dir) / SYSTEMD_CREDENTIAL_NAME
        if path.exists():
            return _read_secret(path)

    privkey_file = os.environ.get(ENV_PRIVKEY_FILE)
    if privkey_file:
        return _read_secret(Path(privkey_file))

    privkey = os.environ.get(ENV_PRIVKEY)
    if privkey:
        return privkey

    raise MissingConfig(
        f"no private key found: set {ENV_PRIVKEY_FILE} or {ENV_PRIVKEY}, or run under "
        f"systemd with LoadCredential={SYSTEMD_CREDENTIAL_NAME}"
    )


def _render_body(alert: Alert) -> str:
    """Nickname, chain and status. Nothing else -- invariant I2. Mirrors email.py's templates;
    kept as its own copy rather than a shared helper, matching channels/__init__.py's
    "each channel is its own module" design -- see that module's docstring."""
    label, chain = alert.label, alert.chain

    if alert.kind is AlertKind.MOVEMENT:
        # See email.py's identical comment: direction is Optional and nothing upstream of this
        # module enforces it, so the alarm must be the default, not the reassurance.
        if alert.direction is Direction.INCOMING:
            return (
                f'"{label}" ({chain}) received a deposit.\n\n'
                "Informational only -- this is not an emergency."
            )
        return (
            f'"{label}" ({chain}) has moved.\n\n'
            "If you hold other seeds or devices, this is the moment to check them -- "
            "attackers sweep sequentially, and this watch may not be the only one at risk."
        )
    if alert.kind is AlertKind.TEST_FIRE:
        return f'This confirms delivery is working for "{label}" ({chain}).\n\nNo action needed.'
    if alert.kind is AlertKind.LOW_BALANCE:
        return (
            f'The balance funding alerts for "{label}" ({chain}) is running low.\n\n'
            "Top it up so this watch does not stop."
        )
    if alert.kind is AlertKind.WATCH_STOPPED:
        return (
            f'The watch "{label}" ({chain}) has stopped.\n\n'
            "It is no longer being monitored until you re-arm it."
        )
    if alert.kind is AlertKind.HEARTBEAT:
        return f'All quiet for "{label}" ({chain}). No movement since the last check.'
    raise ValueError(f"no template for {alert.kind!r}")  # pragma: no cover -- exhaustive above


class RelayConnection(Protocol):
    """What `send`/`recv`/`close` a relay connection needs to provide -- see `_default_connect`
    for the real one and `tests/fake_relay.py` for the test double."""

    def send(self, text: str) -> None: ...
    def recv(self) -> str: ...
    def close(self) -> None: ...


ConnectFn = Callable[[str, float], RelayConnection]


def _classify_note(note: str) -> str:
    prefix = note.split(":", 1)[0].strip().lower() if isinstance(note, str) and note else ""
    return prefix if prefix in _KNOWN_NOTE_PREFIXES else "rejected"


class NostrChannel:
    """`Channel` implementation over NIP-17 gift-wrapped DMs. See the module docstring."""

    kind: ClassVar[str] = "nostr"
    privacy_class: ClassVar[PrivacyClass] = PrivacyClass.E2E_PRIVATE

    def __init__(
        self,
        *,
        privkey: str,
        relays: Sequence[str],
        timeout: float = DEFAULT_TIMEOUT,
        connect: ConnectFn | None = None,
    ) -> None:
        if not relays:
            raise MissingConfig("at least one relay is required")
        for relay in relays:
            if not relay.startswith("wss://"):
                # No opportunistic downgrade, same posture as email.py's implicit-TLS-only
                # connect: a plaintext ws:// relay is rejected at construction, not discovered
                # mid-publish.
                raise ValueError(f"relay must be wss://: {relay!r}")
        try:
            key_length = len(bytes.fromhex(privkey))
        except ValueError:
            raise MissingConfig("private key is not valid hex") from None
        if key_length != 32:
            # coincurve left-pads a short secret rather than rejecting it, which would
            # silently boot the service under a different identity -- see the module
            # docstring's "single published npub" trust anchor.
            raise MissingConfig(f"private key must be 32 bytes, got {key_length}")
        self._privkey = privkey
        self._pubkey = nip01.pubkey_hex_from_privkey(privkey)
        self._relays = tuple(relays)
        self._timeout = timeout
        self._connect = connect or self._default_connect

    def __repr__(self) -> str:
        # pubkey and relays only -- the private key never appears, same discipline as
        # EmailChannel.__repr__ withholding the SMTP password.
        return f"{type(self).__name__}(pubkey={self._pubkey!r}, relays={self._relays!r})"

    @property
    def pubkey(self) -> str:
        return self._pubkey

    @property
    def npub(self) -> str:
        """The service's own bech32 identity -- publish this so users can recognise the
        sender of the seal layer. See the module docstring's "trust anchor" note."""
        return bech32.encode_npub(bytes.fromhex(self._pubkey))

    @classmethod
    def from_env(cls, *, timeout: float = DEFAULT_TIMEOUT) -> NostrChannel:
        """Build from the environment. See `EmailChannel.from_env` for the same pattern."""
        raw_relays = os.environ.get(ENV_RELAYS)
        if not raw_relays:
            raise MissingConfig(f"{ENV_RELAYS} is not set")
        relays = [r for r in raw_relays.replace(",", " ").split() if r]
        return cls(privkey=_read_privkey(), relays=relays, timeout=timeout)

    def _default_connect(self, relay: str, timeout: float) -> RelayConnection:
        # websocket-client verifies the server certificate and hostname by default
        # (cert_reqs=CERT_REQUIRED, check_hostname=True in its _ssl_socket helper) -- no
        # sslopt override needed to get that; see nostr/channel.py's test suite for the
        # construction-time wss:// requirement that keeps this the only TLS path taken.
        return websocket.create_connection(relay, timeout=timeout)

    def validate_dest(self, raw: str) -> str:
        candidate = raw.strip()
        try:
            pubkey = bech32.decode_npub(candidate)
        except ValueError:
            raise ValueError("not a valid npub") from None
        try:
            # x-only pubkeys don't record which y was intended -- 0x02 (even) is the BIP340
            # convention nip44.get_conversation_key also assumes. This only proves the
            # x-coordinate is on the curve at all; roughly half of all 32-byte values aren't.
            PublicKey(b"\x02" + pubkey)
        except ValueError:
            raise ValueError("not a valid npub") from None
        # Hex, not npub, is what's stored and what send() needs -- npub is a display format
        # only (NIP-19 explicitly says it MUST NOT appear in NIP-01 events), so normalising to
        # hex here means send() never has to re-derive it.
        return pubkey.hex()

    def _publish_to(self, relay: str, event: dict) -> tuple[bool, str]:
        conn = self._connect(relay, self._timeout)
        # self._timeout, passed to connect() above, only bounds a single recv() -- a relay that
        # keeps sending frames that are never the OK we're waiting for (NOTICE spam, someone
        # else's subscription traffic) would otherwise reset the clock on every iteration and
        # never time out. This deadline bounds the loop as a whole.
        deadline = time.monotonic() + self._timeout
        try:
            conn.send(json.dumps(["EVENT", event], ensure_ascii=False, separators=(",", ":")))
            while True:
                if time.monotonic() >= deadline:
                    raise websocket.WebSocketTimeoutException("timed out waiting for OK")
                try:
                    frame = json.loads(conn.recv())
                except json.JSONDecodeError:
                    # E.g. recv() returning "" for a CLOSE opcode -- a relay accepting the
                    # EVENT and then hanging up without an OK is routine. Treat as a malformed,
                    # retriable reply rather than letting the exception escape send().
                    return False, "malformed"
                if not isinstance(frame, list) or not frame:
                    continue
                if frame[0] == "OK" and len(frame) >= 3 and frame[1] == event["id"]:
                    note = frame[3] if len(frame) > 3 else ""
                    # `is True`, not `bool(...)`: NIP-01's flag is a JSON bool, but a relay is
                    # untrusted input -- the *string* "false" is truthy and must not read as
                    # delivered.
                    return frame[2] is True, note
                if frame[0] == "CLOSED" and len(frame) >= 2:
                    # NIP-01's CLOSED carries a *subscription* id in frame[1], never an event
                    # id -- this channel never sends a REQ, so any CLOSED here can only be
                    # relay-level (e.g. shutting down), not a match to compare against event["id"].
                    return False, (frame[2] if len(frame) > 2 else "")
                # NOTICE, or an OK/EVENT for someone else's subscription -- keep waiting.
        finally:
            conn.close()

    def send(self, dest: str, alert: Alert) -> DeliveryResult:
        rumor = giftwrap.make_rumor(self._privkey, dest, _render_body(alert))
        seal = giftwrap.make_seal(rumor, self._privkey, dest)
        wrap = giftwrap.make_wrap(seal, dest)

        any_retriable = False
        last_detail = "no relays configured"
        for relay in self._relays:
            try:
                ok, note = self._publish_to(relay, wrap)
            except (OSError, websocket.WebSocketException) as exc:
                # Connection refused, DNS failure, TLS handshake/verification failure, a
                # timeout waiting for OK -- all worth a retry against a relay, none of them
                # this message's fault. Mirrors email.py's OSError handling.
                any_retriable = True
                last_detail = type(exc).__name__
                continue
            if ok:
                return DeliveryResult(ok=True, retriable=False)
            prefix = _classify_note(note)
            if prefix not in _PERMANENT_NOTE_PREFIXES:
                any_retriable = True
            last_detail = prefix

        return DeliveryResult(ok=False, retriable=any_retriable, detail=last_detail)
