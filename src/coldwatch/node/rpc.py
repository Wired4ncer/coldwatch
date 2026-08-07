"""A minimal bitcoind JSON-RPC client.

Stdlib only. The service declares no runtime dependencies and this is not the place to start:
an RPC client is a POST with a JSON body, and a dependency here would sit in the path of every
call the service makes to its own node.

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

__all__ = ["BitcoinRpc", "RpcError", "RpcTransportError"]

DEFAULT_TIMEOUT = 30.0


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
