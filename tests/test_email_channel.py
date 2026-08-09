"""EmailChannel — issue #2.

Uses `FakeSmtp` (an in-process stand-in, see `fake_smtp.py`) rather than a real server: what
matters here is this module's own logic, not smtplib's already-tested transport behaviour.
"""

from __future__ import annotations

import smtplib
import ssl
from datetime import UTC, datetime

import pytest

from coldwatch.channels import AlertKind, Direction, PrivacyClass
from coldwatch.channels.base import Alert
from coldwatch.channels.email import SUBJECT, EmailChannel, MissingConfig
from fake_smtp import FakeSmtp


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


def make_channel(fake: FakeSmtp, **overrides) -> EmailChannel:
    kwargs = {
        "host": "smtp.example.invalid",
        "user": "svc",
        "password": "hunter2",
        "from_addr": "alerts@example.invalid",
        "connect": lambda: fake,
    }
    kwargs.update(overrides)
    return EmailChannel(**kwargs)


# ── kind / privacy_class ─────────────────────────────────────────────────────────────────────


def test_declares_itself_provider_reads():
    """Email is the weakest privacy class — the enrolment gate (#23) depends on this being
    honest, not on a channel author remembering to tell the truth in a UI somewhere."""
    assert EmailChannel.kind == "email"
    assert EmailChannel.privacy_class is PrivacyClass.PROVIDER_READS


def test_satisfies_the_channel_protocol():
    from coldwatch.channels.base import Channel

    fake = FakeSmtp()
    assert isinstance(make_channel(fake), Channel)


# ── validate_dest ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("user@example.com", "user@example.com"),
        ("  user@example.com  ", "user@example.com"),
        ("User@Example.com", "user@example.com"),
    ],
)
def test_validate_dest_normalises(raw, expected):
    fake = FakeSmtp()
    assert make_channel(fake).validate_dest(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not-an-email",
        "user@",
        "@example.com",
        "user@example",  # no TLD
        "user example.com",
        "Name <user@example.com>",  # display-name form rejected: only a bare address
        "user@example.com\r\nBcc: evil@example.com",  # header-injection attempt
    ],
)
def test_validate_dest_rejects_junk(raw):
    fake = FakeSmtp()
    with pytest.raises(ValueError):
        make_channel(fake).validate_dest(raw)


# ── send: success ────────────────────────────────────────────────────────────────────────────


def test_send_success():
    fake = FakeSmtp()
    channel = make_channel(fake)
    result = channel.send("user@example.com", make_alert())

    assert result.ok is True
    assert result.retriable is False
    assert result.detail == ""
    assert fake.logins == [("svc", "hunter2")]
    assert len(fake.sent) == 1
    assert fake.closed is True


def test_subject_is_the_constant_regardless_of_alert():
    """Invariant: the subject must not vary with the alert — see the module docstring on why."""
    fake = FakeSmtp()
    channel = make_channel(fake)

    for kind, direction in [
        (AlertKind.MOVEMENT, Direction.OUTGOING),
        (AlertKind.MOVEMENT, Direction.INCOMING),
        (AlertKind.TEST_FIRE, None),
        (AlertKind.LOW_BALANCE, None),
        (AlertKind.WATCH_STOPPED, None),
        (AlertKind.HEARTBEAT, None),
    ]:
        channel.send("user@example.com", make_alert(kind=kind, direction=direction))

    assert {msg["Subject"] for msg in fake.sent} == {SUBJECT}


def test_send_uses_the_validated_destination_as_the_recipient():
    fake = FakeSmtp()
    channel = make_channel(fake)
    channel.send("user@example.com", make_alert())
    assert fake.sent[0]["To"] == "user@example.com"


# ── send: failure classification ────────────────────────────────────────────────────────────


def test_send_permanent_failure_is_not_retriable():
    fake = FakeSmtp(send_error=smtplib.SMTPDataError(550, b"mailbox unavailable"))
    result = make_channel(fake).send("user@example.com", make_alert())
    assert result.ok is False
    assert result.retriable is False


def test_send_transient_failure_is_retriable():
    fake = FakeSmtp(send_error=smtplib.SMTPDataError(450, b"try again later"))
    result = make_channel(fake).send("user@example.com", make_alert())
    assert result.ok is False
    assert result.retriable is True


def test_recipients_refused_is_a_permanent_failure():
    fake = FakeSmtp(send_error=smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"no")}))
    result = make_channel(fake).send("user@example.com", make_alert())
    assert result.ok is False
    assert result.retriable is False


def test_auth_failure_is_a_permanent_failure():
    fake = FakeSmtp(login_error=smtplib.SMTPAuthenticationError(535, b"bad credentials"))
    result = make_channel(fake).send("user@example.com", make_alert())
    assert result.ok is False
    assert result.retriable is False


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("connection refused"),
        TimeoutError("timed out"),
        ssl.SSLError("certificate verify failed"),
        smtplib.SMTPServerDisconnected("connection closed"),
    ],
)
def test_transport_failures_are_retriable(error):
    fake = FakeSmtp(send_error=error)
    result = make_channel(fake).send("user@example.com", make_alert())
    assert result.ok is False
    assert result.retriable is True


# ── invariant I1 / I2: nothing sensitive ever reaches DeliveryResult.detail ────────────────


FORBIDDEN_IN_DETAIL = ("user@example.com", "hunter2", "address", "sats", "txid")


@pytest.mark.parametrize(
    "error",
    [
        smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"mailbox for user@example.com")}),
        smtplib.SMTPDataError(550, b"rejected user@example.com: policy"),
        smtplib.SMTPAuthenticationError(535, b"bad credentials: hunter2"),
    ],
)
def test_delivery_result_detail_never_contains_the_destination_or_secrets(error):
    fake = FakeSmtp(send_error=error)
    result = make_channel(fake).send("user@example.com", make_alert())
    for forbidden in FORBIDDEN_IN_DETAIL:
        assert forbidden not in result.detail


def test_delivery_result_detail_never_contains_the_destination_on_login_failure():
    fake = FakeSmtp(login_error=smtplib.SMTPAuthenticationError(535, b"bad credentials: hunter2"))
    result = make_channel(fake).send("user@example.com", make_alert())
    for forbidden in FORBIDDEN_IN_DETAIL:
        assert forbidden not in result.detail


# ── templates: no template can emit an address, amount or txid ─────────────────────────────


FORBIDDEN_IN_BODY = (
    "address", "addr", "amount", "sats", "satoshi",
    "txid", "tx_id", "transaction", "outpoint", "script",
    "height", "block", "fee", "balance:",
)


@pytest.mark.parametrize(
    "kind,direction",
    [
        (AlertKind.MOVEMENT, Direction.OUTGOING),
        (AlertKind.MOVEMENT, Direction.INCOMING),
        (AlertKind.TEST_FIRE, None),
        (AlertKind.LOW_BALANCE, None),
        (AlertKind.WATCH_STOPPED, None),
        (AlertKind.HEARTBEAT, None),
    ],
)
def test_no_template_leaks_chain_data(kind, direction):
    fake = FakeSmtp()
    channel = make_channel(fake)
    channel.send("user@example.com", make_alert(kind=kind, direction=direction))

    body = fake.sent[0].get_content().lower()
    for forbidden in FORBIDDEN_IN_BODY:
        assert forbidden not in body, f"{kind}/{direction} template leaked {forbidden!r}"


def test_outgoing_movement_reads_as_an_alarm_and_incoming_does_not():
    """README design principle: outgoing is an alarm, incoming is information."""
    fake = FakeSmtp()
    channel = make_channel(fake)

    channel.send("user@example.com", make_alert(direction=Direction.OUTGOING))
    channel.send("user@example.com", make_alert(direction=Direction.INCOMING))

    outgoing_body = fake.sent[0].get_content()
    incoming_body = fake.sent[1].get_content()
    assert "has moved" in outgoing_body
    assert "check them" in outgoing_body
    assert "received a deposit" in incoming_body
    assert "not an emergency" in incoming_body


# ── from_env / MissingConfig ─────────────────────────────────────────────────────────────────


def test_from_env_requires_user(monkeypatch):
    monkeypatch.delenv("COLDWATCH_SMTP_USER", raising=False)
    monkeypatch.setenv("COLDWATCH_SMTP_FROM", "alerts@example.invalid")
    monkeypatch.setenv("COLDWATCH_SMTP_HOST", "smtp.example.invalid")
    with pytest.raises(MissingConfig, match="COLDWATCH_SMTP_USER"):
        EmailChannel.from_env()


def test_from_env_requires_password(monkeypatch):
    monkeypatch.setenv("COLDWATCH_SMTP_USER", "svc")
    monkeypatch.setenv("COLDWATCH_SMTP_FROM", "alerts@example.invalid")
    monkeypatch.setenv("COLDWATCH_SMTP_HOST", "smtp.example.invalid")
    monkeypatch.delenv("COLDWATCH_SMTP_PASSWORD", raising=False)
    monkeypatch.delenv("COLDWATCH_SMTP_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(MissingConfig, match="COLDWATCH_SMTP_PASSWORD"):
        EmailChannel.from_env()


def test_from_env_reads_password_from_file(monkeypatch, tmp_path):
    password_file = tmp_path / "smtp-password"
    password_file.write_text("hunter2\n")

    monkeypatch.setenv("COLDWATCH_SMTP_USER", "svc")
    monkeypatch.setenv("COLDWATCH_SMTP_FROM", "alerts@example.invalid")
    monkeypatch.setenv("COLDWATCH_SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("COLDWATCH_SMTP_PASSWORD_FILE", str(password_file))
    monkeypatch.delenv("COLDWATCH_SMTP_PASSWORD", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

    channel = EmailChannel.from_env()
    assert channel._password == "hunter2"


def test_repr_never_contains_the_password():
    fake = FakeSmtp()
    channel = make_channel(fake, password="hunter2")
    assert "hunter2" not in repr(channel)


# ── TLS default ──────────────────────────────────────────────────────────────────────────────


def test_default_connect_uses_implicit_tls(monkeypatch):
    """No opportunistic downgrade: proves the *default* path is SMTP_SSL, not STARTTLS, without
    needing a live TLS handshake — see the module docstring."""
    calls = []

    class _RecordingSMTPSSL:
        def __init__(self, host, port, timeout, context):
            calls.append((host, port, timeout, context))

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def login(self, user, password):
            pass

        def send_message(self, message):
            pass

    monkeypatch.setattr(smtplib, "SMTP_SSL", _RecordingSMTPSSL)
    channel = EmailChannel(
        host="smtp.example.invalid",
        user="svc",
        password="hunter2",
        from_addr="alerts@example.invalid",
    )
    channel.send("user@example.com", make_alert())

    assert len(calls) == 1
    host, port, _timeout, context = calls[0]
    assert host == "smtp.example.invalid"
    assert port == 465
    assert isinstance(context, ssl.SSLContext)
