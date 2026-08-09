"""An in-process stand-in for the object `EmailChannel` calls, for testing without a mail server.

Mirrors `fake_node.py`: TLS and the SMTP wire protocol are smtplib's job, already exercised by
its own test suite, and re-proving them here would just be testing the standard library. What
is worth checking is `EmailChannel`'s own logic — which template fires, that the subject never
varies, and that an SMTP failure turns into the right `DeliveryResult` without the destination
or the message body leaking into it. So this fakes the connected client, not the socket
underneath it — injected via `EmailChannel(..., connect=lambda: fake)`.
"""

from __future__ import annotations

from email.message import EmailMessage
from typing import Self

__all__ = ["FakeSmtp"]


class FakeSmtp:
    """Programmable stand-in for a connected `smtplib.SMTP`/`SMTP_SSL` instance."""

    def __init__(
        self,
        *,
        login_error: Exception | None = None,
        send_error: Exception | None = None,
    ) -> None:
        self.login_error = login_error
        self.send_error = send_error
        self.logins: list[tuple[str, str]] = []
        self.sent: list[EmailMessage] = []
        self.closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.closed = True
        return False

    def login(self, user: str, password: str) -> None:
        self.logins.append((user, password))
        if self.login_error is not None:
            raise self.login_error

    def send_message(self, message: EmailMessage) -> None:
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(message)
