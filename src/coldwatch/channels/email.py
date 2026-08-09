"""Email delivery channel (issue #2) — the first rail, chosen for reach.

Stdlib only: `smtplib`, `email`, `ssl`. The runtime's one third-party dependency is `pyzmq`
(see SECURITY.md) and a mail client is not a reason to add a second — everything needed here
already ships with Python.

Two things this module is deliberately careful about, because email is the weakest privacy
class a channel can have (`PrivacyClass.PROVIDER_READS` — the operator's mail provider reads
both content and metadata):

- **The subject line never varies.** It is a module-level constant, not a template input,
  because a subject is logged and indexed at every hop between here and the recipient's inbox.
  A subject that changed with the alert would itself be a side channel.
- **TLS is not negotiated, it is assumed.** The connection is wrapped in TLS from the first
  byte (implicit TLS / SMTPS), so there is no STARTTLS handshake for a network position to
  strip. See `_default_connect`.

`privacy_ack` (the user's explicit acknowledgement that email is provider-read) is an
enrolment-time gate — see docs/architecture.md §5 and issue #23 — and is out of scope here:
this module only needs to expose `privacy_class` honestly so that gate can be built against it.
"""

from __future__ import annotations

import os
import re
import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path
from typing import ClassVar

from coldwatch.channels.base import Alert, AlertKind, DeliveryResult, Direction, PrivacyClass

__all__ = ["EmailChannel", "MissingConfig"]

#: Constant on purpose — see module docstring.
SUBJECT = "cold.watch alert"

DEFAULT_PORT = 465  # implicit TLS (SMTPS) — see _default_connect.
DEFAULT_TIMEOUT = 30.0

ENV_HOST = "COLDWATCH_SMTP_HOST"
ENV_PORT = "COLDWATCH_SMTP_PORT"
ENV_USER = "COLDWATCH_SMTP_USER"
ENV_PASSWORD = "COLDWATCH_SMTP_PASSWORD"
ENV_PASSWORD_FILE = "COLDWATCH_SMTP_PASSWORD_FILE"
ENV_FROM_ADDR = "COLDWATCH_SMTP_FROM"

#: Mirrors node.rpc: systemd's LoadCredential is preferred over a bare environment variable,
#: because an environment is readable from /proc/<pid>/environ and inherited by every child
#: process. See node/rpc.py for the full reasoning.
ENV_SYSTEMD_CREDENTIALS = "CREDENTIALS_DIRECTORY"
SYSTEMD_CREDENTIAL_NAME = "smtp-password"

#: Deliberately strict: no display name, no comments, no whitespace of any kind (which also
#: rules out a bare '\r' or '\n' reaching a header). A destination that fails this is rejected
#: at enrolment rather than discovered undeliverable later.
_ADDR_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ConnectFn = Callable[[], smtplib.SMTP]


class MissingConfig(Exception):
    """A required setting was not found. Names the variable, never a value.

    ⚠️ This is the exception most likely to be pasted into an issue by someone asking for help
    — see node/rpc.py's `MissingCredentials`, which this mirrors.
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


def _read_password() -> str:
    credentials_dir = os.environ.get(ENV_SYSTEMD_CREDENTIALS)
    if credentials_dir:
        path = Path(credentials_dir) / SYSTEMD_CREDENTIAL_NAME
        if path.exists():
            return _read_secret(path)

    password_file = os.environ.get(ENV_PASSWORD_FILE)
    if password_file:
        return _read_secret(Path(password_file))

    password = os.environ.get(ENV_PASSWORD)
    if password:
        return password

    raise MissingConfig(
        f"no password found: set {ENV_PASSWORD_FILE} or {ENV_PASSWORD}, or run under "
        f"systemd with LoadCredential={SYSTEMD_CREDENTIAL_NAME}"
    )


def _render_body(alert: Alert) -> str:
    """Nickname, chain and status. Nothing else — invariant I2, and see test_email_channel.py."""
    label, chain = alert.label, alert.chain

    if alert.kind is AlertKind.MOVEMENT:
        if alert.direction is Direction.OUTGOING:
            return (
                f'"{label}" ({chain}) has moved.\n\n'
                "If you hold other seeds or devices, this is the moment to check them — "
                "attackers sweep sequentially, and this watch may not be the only one at risk."
            )
        return (
            f'"{label}" ({chain}) received a deposit.\n\n'
            "Informational only — this is not an emergency."
        )
    if alert.kind is AlertKind.TEST_FIRE:
        return (
            f'This confirms delivery is working for "{label}" ({chain}).\n\nNo action needed.'
        )
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
    raise ValueError(f"no template for {alert.kind!r}")  # pragma: no cover — exhaustive above


class EmailChannel:
    """`Channel` implementation over SMTP. See the module docstring for the privacy posture."""

    kind: ClassVar[str] = "email"
    privacy_class: ClassVar[PrivacyClass] = PrivacyClass.PROVIDER_READS

    def __init__(
        self,
        *,
        host: str,
        port: int = DEFAULT_PORT,
        user: str,
        password: str,
        from_addr: str,
        timeout: float = DEFAULT_TIMEOUT,
        connect: ConnectFn | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._from_addr = from_addr
        self._timeout = timeout
        #: Test seam. Production never overrides this — see `_default_connect`. Tests inject a
        #: callable that returns an in-process fake (`tests/fake_smtp.py`), the same way
        #: `test_rpc.py`'s `serve()` stands in for a real node, so the logic here is exercised
        #: without a mail server or a TLS handshake to fake.
        self._connect = connect or self._default_connect

    def __repr__(self) -> str:
        # Host, port and the sender address only — everything else here is a credential.
        return f"{type(self).__name__}({self._host}:{self._port}, from={self._from_addr!r})"

    @classmethod
    def from_env(cls, *, timeout: float = DEFAULT_TIMEOUT) -> EmailChannel:
        """Build from the environment. See `node.rpc.BitcoinRpc.from_env` for the same pattern.

        The password is never an argument, never a literal in a file that could be committed,
        and never something a human reads out loud — see `_read_password`.
        """
        user = os.environ.get(ENV_USER)
        if not user:
            raise MissingConfig(f"{ENV_USER} is not set")

        from_addr = os.environ.get(ENV_FROM_ADDR)
        if not from_addr:
            raise MissingConfig(f"{ENV_FROM_ADDR} is not set")

        host = os.environ.get(ENV_HOST)
        if not host:
            raise MissingConfig(f"{ENV_HOST} is not set")

        return cls(
            host=host,
            port=int(os.environ.get(ENV_PORT, str(DEFAULT_PORT))),
            user=user,
            password=_read_password(),
            from_addr=from_addr,
            timeout=timeout,
        )

    def _default_connect(self) -> smtplib.SMTP:
        # Implicit TLS from the first byte on the wire (SMTPS, port 465 by default) — there is
        # no STARTTLS negotiation here for a network position to downgrade or strip.
        return smtplib.SMTP_SSL(
            self._host, self._port, timeout=self._timeout, context=ssl.create_default_context()
        )

    def validate_dest(self, raw: str) -> str:
        candidate = raw.strip()
        if not candidate or not _ADDR_RE.match(candidate):
            raise ValueError("not a valid email address")
        return candidate.lower()

    def send(self, dest: str, alert: Alert) -> DeliveryResult:
        message = EmailMessage()
        message["Subject"] = SUBJECT
        message["From"] = self._from_addr
        message["To"] = dest
        message.set_content(_render_body(alert))

        try:
            with self._connect() as smtp:
                smtp.login(self._user, self._password)
                smtp.send_message(message)
        except smtplib.SMTPRecipientsRefused:
            # .recipients on this exception carries the destination back — never touch it here.
            return DeliveryResult(ok=False, retriable=False, detail="recipient refused")
        except smtplib.SMTPResponseException as exc:
            # 4xx is transient by SMTP convention (e.g. greylisting, mailbox temporarily full);
            # 5xx is permanent (bad auth, unknown user, policy rejection).
            retriable = 400 <= exc.smtp_code < 500
            return DeliveryResult(ok=False, retriable=retriable, detail=f"smtp {exc.smtp_code}")
        except smtplib.SMTPException as exc:
            return DeliveryResult(ok=False, retriable=True, detail=type(exc).__name__)
        except OSError as exc:
            # Connection refused, DNS failure, TLS handshake/verification failure (ssl.SSLError
            # is a subclass of OSError) — all worth a retry, none of them the message's fault.
            return DeliveryResult(ok=False, retriable=True, detail=type(exc).__name__)

        return DeliveryResult(ok=True, retriable=False)
