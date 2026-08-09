"""Where the RPC password comes from, and where it must never end up.

The whole point of `from_env` is that the password never passes through a caller, a command
line, or a file anyone might commit. These tests assert the sources work — and, more
importantly, that nothing carries the value outward when they do not.
"""

from __future__ import annotations

import pytest

from coldwatch.node.rpc import (
    ENV_PASSWORD,
    ENV_PASSWORD_FILE,
    ENV_SYSTEMD_CREDENTIALS,
    ENV_USER,
    SYSTEMD_CREDENTIAL_NAME,
    BitcoinRpc,
    MissingCredentials,
)

SECRET = "correct-horse-battery-staple"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """A real password in the developer's own environment would make these pass for the wrong
    reason — or worse, put it somewhere a test could print it."""
    for name in (
        ENV_USER,
        ENV_PASSWORD,
        ENV_PASSWORD_FILE,
        ENV_SYSTEMD_CREDENTIALS,
        "COLDWATCH_RPC_HOST",
        "COLDWATCH_RPC_PORT",
    ):
        monkeypatch.delenv(name, raising=False)


def auth_of(rpc: BitcoinRpc) -> str:
    """The credential as it actually goes on the wire, decoded."""
    import base64

    return base64.b64decode(rpc._auth).decode()


# ── the three sources ───────────────────────────────────────────────────────────────────────


def test_the_password_can_come_from_the_environment(monkeypatch):
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD, SECRET)

    assert auth_of(BitcoinRpc.from_env()) == f"aw:{SECRET}"


def test_a_file_is_preferred_over_the_environment(monkeypatch, tmp_path):
    """A file can be read by one user; an environment is readable from /proc/<pid>/environ and
    is inherited by every child process. When both exist, the better one wins."""
    path = tmp_path / "rpc-password"
    path.write_text(SECRET + "\n")
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD, "this-one-should-lose")
    monkeypatch.setenv(ENV_PASSWORD_FILE, str(path))

    assert auth_of(BitcoinRpc.from_env()) == f"aw:{SECRET}"


def test_systemd_credentials_win_over_both(monkeypatch, tmp_path):
    """`LoadCredential=` is the deployment path: a file only the unit can read."""
    (tmp_path / SYSTEMD_CREDENTIAL_NAME).write_text(SECRET)
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD, "loses")
    monkeypatch.setenv(ENV_SYSTEMD_CREDENTIALS, str(tmp_path))

    assert auth_of(BitcoinRpc.from_env()) == f"aw:{SECRET}"


def test_a_credentials_directory_without_our_file_falls_through(monkeypatch, tmp_path):
    """Running under systemd with *some* credential loaded, but not this one, must not be a
    hard failure — the other sources are still valid."""
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_SYSTEMD_CREDENTIALS, str(tmp_path))
    monkeypatch.setenv(ENV_PASSWORD, SECRET)

    assert auth_of(BitcoinRpc.from_env()) == f"aw:{SECRET}"


def test_only_the_trailing_newline_is_stripped(monkeypatch, tmp_path):
    """An editor adds one. A password with meaningful leading whitespace is still a password,
    and silently trimming it produces an auth failure nobody can explain."""
    path = tmp_path / "rpc-password"
    path.write_text(f"  {SECRET}  \n")
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD_FILE, str(path))

    assert auth_of(BitcoinRpc.from_env()) == f"aw:  {SECRET}  "


# ── what the failures may say ───────────────────────────────────────────────────────────────


def test_a_missing_user_names_the_variable(monkeypatch):
    monkeypatch.setenv(ENV_PASSWORD, SECRET)

    with pytest.raises(MissingCredentials) as caught:
        BitcoinRpc.from_env()

    assert ENV_USER in str(caught.value)


def test_a_missing_password_names_the_sources_and_no_value(monkeypatch):
    monkeypatch.setenv(ENV_USER, "aw")

    with pytest.raises(MissingCredentials) as caught:
        BitcoinRpc.from_env()

    message = str(caught.value)
    assert ENV_PASSWORD_FILE in message and SYSTEMD_CREDENTIAL_NAME in message


def test_an_unreadable_file_reports_the_path_and_not_the_contents(monkeypatch, tmp_path):
    path = tmp_path / "nope"
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD_FILE, str(path))

    with pytest.raises(MissingCredentials) as caught:
        BitcoinRpc.from_env()

    assert str(path) in str(caught.value)


def test_an_empty_file_is_refused_rather_than_used(monkeypatch, tmp_path):
    """An empty credential authenticates as nothing and produces a confusing 401 much later."""
    path = tmp_path / "rpc-password"
    path.write_text("\n")
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD_FILE, str(path))

    with pytest.raises(MissingCredentials):
        BitcoinRpc.from_env()


# ── the value must not escape ───────────────────────────────────────────────────────────────


def test_the_password_is_in_no_representation_of_the_client(monkeypatch):
    """`repr` lands in tracebacks, log lines and issue reports. This is the assertion that
    stops someone adding a helpful `user=` to it later."""
    monkeypatch.setenv(ENV_USER, "aw")
    monkeypatch.setenv(ENV_PASSWORD, SECRET)

    rpc = BitcoinRpc.from_env()

    assert SECRET not in repr(rpc)
    assert SECRET not in str(vars(rpc))  # not just repr: the base64 blob is the credential too
