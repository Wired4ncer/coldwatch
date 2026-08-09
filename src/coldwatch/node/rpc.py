"""A minimal bitcoind JSON-RPC client.

Stdlib only. The runtime has exactly one third-party dependency (`pyzmq`, because bitcoind
publishes over ZMQ and there is no standard-library client) and this is not the place to add a
second: an RPC client is a POST with a JSON body, and a dependency here would sit in the path of
every call the service makes to its own node.

Two properties matter more than features:

**Credentials never appear anywhere but the Authorization header.** Not in a URL, not in
``repr``, not in an exception message. A connection string with the password in it ends up in
a traceback the first time the node is down, and a traceback is exactly what gets pasted into
an issue.

**Every call opens its own connection.** `scantxoutset start` blocks for minutes, and `abort`
has to reach the node *while* it is blocked. Sharing one connection would queue the abort
behind the scan it is trying to cancel — the deadlock version of the orphaned-scan problem.
"""

from __future__ import annotations

import base64
import http.client
import itertools
import json
import os
from pathlib import Path

__all__ = ["BitcoinRpc", "MissingCredentials", "RpcError", "RpcTransportError"]

DEFAULT_TIMEOUT = 30.0

#: Where credentials come from, in the order they are tried. Names rather than values appear in
#: every error this module raises — see `MissingCredentials`.
ENV_HOST = "COLDWATCH_RPC_HOST"
ENV_PORT = "COLDWATCH_RPC_PORT"
ENV_USER = "COLDWATCH_RPC_USER"
ENV_PASSWORD = "COLDWATCH_RPC_PASSWORD"
ENV_PASSWORD_FILE = "COLDWATCH_RPC_PASSWORD_FILE"

#: systemd sets this for units using `LoadCredential=`, pointing at a directory of files the
#: unit may read and nothing else may. Preferred over an environment variable because an
#: environment is readable from `/proc/<pid>/environ` and inherited by every child process.
ENV_SYSTEMD_CREDENTIALS = "CREDENTIALS_DIRECTORY"
SYSTEMD_CREDENTIAL_NAME = "rpc-password"


def _read_secret(path: Path) -> str:
    """Read a credential from a file, stripping the trailing newline an editor adds.

    ⚠️ Only the *whitespace around* the value is stripped, never characters inside it — a
    password with a leading space is a password, and silently correcting it would produce an
    authentication failure nobody can explain.
    """
    try:
        secret = path.read_text()
    except OSError as exc:
        # errno and the path, never the contents — a partially-read secret in a message is
        # still a secret.
        raise MissingCredentials(f"could not read {path}: {exc.strerror}") from None
    secret = secret.rstrip("\r\n")
    if not secret:
        raise MissingCredentials(f"{path} is empty")
    return secret


class MissingCredentials(Exception):
    """No credential was found, or the one named could not be read.

    ⚠️ Every message this raises names the **variable or path**, never a value or any part of
    one. "The password is 12 characters" is a useful hint to someone who should not have it, and
    this exception is the one most likely to be pasted into an issue by someone asking for help.
    """


class RpcError(Exception):
    """The node answered, and the answer was an error.

    ⚠️ ``message`` is the node's own text and may quote the arguments it rejected — including a
    descriptor, which contains a watched scriptPubKey. Do not log it. Callers that surface
    errors outward should report :attr:`code` and their own wording; see how
    `node.supervisor` converts these into `ScanFailed`.
    """

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"rpc error {code}")
        self.code = code
        self.message = message

    def __str__(self) -> str:
        # Deliberately not the node's message: this string lands in logs and tracebacks.
        return f"rpc error {self.code}"


class RpcTransportError(Exception):
    """The node could not be reached, or answered with something that is not JSON-RPC."""


class BitcoinRpc:
    """One node, addressed over HTTP. Thread-safe because it shares nothing between calls."""

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._host = host
        self._port = port
        self._auth = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        self._timeout = timeout
        self._ids = itertools.count(1)

    def __repr__(self) -> str:
        # Host and port only. Everything else here is a credential.
        return f"{type(self).__name__}({self._host}:{self._port})"

    @classmethod
    def from_env(cls, *, timeout: float = DEFAULT_TIMEOUT) -> BitcoinRpc:
        """Build a client from the environment, without the password passing through a caller.

        Three sources, in descending order of how well they contain the secret:

        1. **systemd's `LoadCredential`** — `$CREDENTIALS_DIRECTORY/rpc-password`, a file only
           this unit can read. This is the deployment path, and it is first because an
           environment variable is readable from `/proc/<pid>/environ` and is inherited by every
           child process the service ever spawns.
        2. **`COLDWATCH_RPC_PASSWORD_FILE`** — any path. The same property without systemd.
        3. **`COLDWATCH_RPC_PASSWORD`** — the variable itself. Convenient for a one-off run from
           a shell; the weakest of the three, and deliberately last.

        The point of all three is the same: **the password is never an argument, never a literal
        in a file that could be committed, and never something a human reads out to anyone.**
        A one-off run can put it in the environment with `read -rs` so it is not in shell history
        either.
        """
        user = os.environ.get(ENV_USER)
        if not user:
            raise MissingCredentials(f"{ENV_USER} is not set")

        password = cls._read_password()
        return cls(
            host=os.environ.get(ENV_HOST, "127.0.0.1"),
            port=int(os.environ.get(ENV_PORT, "8332")),
            user=user,
            password=password,
            timeout=timeout,
        )

    @staticmethod
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

        raise MissingCredentials(
            f"no password found: set {ENV_PASSWORD_FILE} or {ENV_PASSWORD}, or run under "
            f"systemd with LoadCredential={SYSTEMD_CREDENTIAL_NAME}"
        )

    def call(self, method: str, *params: object, timeout: float | None = None) -> object:
        """Issue one call and return its ``result``.

        ``timeout`` overrides the default for this call. It is not optional in spirit: a read
        timeout shorter than a scan **causes** the orphan it is meant to avoid, because
        abandoning the HTTP request does not stop the scan on the node. See
        `node.supervisor.ScanSupervisor.scan_timeout`.
        """
        body = json.dumps(
            {"jsonrpc": "1.0", "id": next(self._ids), "method": method, "params": list(params)}
        )
        conn = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout if timeout is None else timeout
        )
        try:
            conn.request(
                "POST",
                "/",
                body=body,
                headers={
                    "Authorization": f"Basic {self._auth}",
                    "Content-Type": "application/json",
                },
            )
            raw = conn.getresponse().read()
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            # `exc` may name the host; it cannot name the credentials, which never leave the
            # header. Keep the type and drop the rest rather than reformat someone else's text.
            raise RpcTransportError(f"{method}: {type(exc).__name__}") from None
        finally:
            conn.close()

        # bitcoind answers an RPC error with HTTP 500 and a JSON-RPC body, so the status line
        # is not the thing to branch on — the body is.
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise RpcTransportError(f"{method}: response was not JSON") from None
        if not isinstance(payload, dict):
            raise RpcTransportError(f"{method}: response was not a JSON-RPC object")

        error = payload.get("error")
        if error is not None:
            if isinstance(error, dict):
                raise RpcError(int(error.get("code", -1)), str(error.get("message", "")))
            raise RpcTransportError(f"{method}: malformed error object")
        if "result" not in payload:
            raise RpcTransportError(f"{method}: response had neither result nor error")
        return payload["result"]
