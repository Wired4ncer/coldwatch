"""The RPC client, against a real socket.

Short tests over a real `http.server` rather than a mocked transport, because the things worth
checking here are transport behaviours: that an RPC error arriving as HTTP 500 is read as an
error rather than a dead connection, that a timeout raises rather than hangs, and that the
credentials go in the header and nowhere else.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from coldwatch.node.rpc import BitcoinRpc, RpcError, RpcTransportError

PASSWORD = "correct-horse-battery-staple"


def serve(handler_fn):
    """Run a one-off HTTP server and yield a client pointed at it."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            request = json.loads(self.rfile.read(length) or b"{}")
            status, body = handler_fn(request, self.headers)
            payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # A short poll interval purely so `shutdown()` returns promptly: the default is 0.5 s,
    # and paying that per test dominated the suite once there were a dozen of them.
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    ).start()
    return server


@pytest.fixture
def node():
    """(client, record) — `record` collects what the server saw."""
    record: dict = {"requests": [], "headers": [], "response": (200, None), "delay": 0.0}

    def handler(request, headers):
        record["requests"].append(request)
        record["headers"].append(dict(headers))
        if record["delay"]:
            time.sleep(record["delay"])
        status, body = record["response"]
        if body is None:
            body = {"result": "ok", "error": None, "id": request.get("id")}
        return status, body

    server = serve(handler)
    client = BitcoinRpc("127.0.0.1", server.server_address[1], "rpcuser", PASSWORD, timeout=2.0)
    yield client, record
    server.shutdown()


# ── the happy path and the shape of a call ──────────────────────────────────────────────────


def test_a_result_comes_back(node):
    client, record = node
    assert client.call("getblockcount", 1, "two") == "ok"

    sent = record["requests"][0]
    assert sent["method"] == "getblockcount"
    assert sent["params"] == [1, "two"]


def test_request_ids_are_distinct(node):
    """Not strictly required over one connection per call, but a repeated id is the kind of
    thing that only becomes a bug once something starts pipelining."""
    client, record = node
    client.call("uptime")
    client.call("uptime")
    assert record["requests"][0]["id"] != record["requests"][1]["id"]


# ── errors ──────────────────────────────────────────────────────────────────────────────────


def test_an_rpc_error_arrives_as_http_500_and_is_still_an_rpc_error(node):
    """bitcoind answers a rejected call with HTTP 500 *and* a JSON-RPC body. Branching on the
    status line would turn every ordinary rejection into a transport failure, and the
    supervisor would retry things that will never succeed."""
    client, record = node
    record["response"] = (500, {"result": None, "error": {"code": -8, "message": "nope"}, "id": 1})

    with pytest.raises(RpcError) as exc:
        client.call("scantxoutset", "start")
    assert exc.value.code == -8
    assert exc.value.message == "nope"


def test_an_rpc_error_string_does_not_repeat_the_nodes_message(node):
    """`str(exc)` is what lands in a log or a traceback. The node's message may quote the
    descriptor it rejected, and a descriptor contains a watched scriptPubKey."""
    client, record = node
    secret_script = "0014" + "cd" * 20
    record["response"] = (
        500,
        {"result": None, "error": {"code": -5, "message": f"bad raw({secret_script})"}, "id": 1},
    )

    with pytest.raises(RpcError) as exc:
        client.call("scantxoutset", "start")
    assert secret_script not in str(exc.value)
    assert secret_script in exc.value.message  # available for a caller that knows better


def test_a_non_json_body_is_a_transport_error(node):
    client, record = node
    record["response"] = (200, "<html>bitcoind is not ready</html>")
    with pytest.raises(RpcTransportError):
        client.call("getblockcount")


def test_a_body_with_neither_result_nor_error_is_a_transport_error(node):
    client, record = node
    record["response"] = (200, {"id": 1})
    with pytest.raises(RpcTransportError):
        client.call("getblockcount")


def test_an_unreachable_node_raises_rather_than_hangs():
    client = BitcoinRpc("127.0.0.1", 1, "u", "p", timeout=1.0)
    with pytest.raises(RpcTransportError):
        client.call("getblockcount")


def test_a_slow_response_times_out(node):
    """A hung call would wedge the supervisor's only worker thread, and with it every enrolment
    behind it."""
    client, record = node
    record["delay"] = 2.0
    with pytest.raises(RpcTransportError):
        client.call("getblockcount", timeout=0.2)


def test_a_per_call_timeout_can_exceed_the_default(node):
    """`scantxoutset start` blocks for minutes. Without a per-call override it would inherit a
    default that abandons the scan — and abandoning it does not stop it."""
    client, record = node
    record["delay"] = 0.3
    assert client.call("getblockcount", timeout=5.0) == "ok"


# ── credentials ─────────────────────────────────────────────────────────────────────────────


def test_credentials_travel_only_in_the_authorization_header(node):
    client, record = node
    client.call("uptime")

    headers = record["headers"][0]
    assert headers["Authorization"].startswith("Basic ")
    for name, value in headers.items():
        if name != "Authorization":
            assert PASSWORD not in value
    assert PASSWORD not in json.dumps(record["requests"][0])


def test_repr_shows_where_it_points_and_nothing_else(node):
    """A `repr` ends up in tracebacks, logs and debugger output. A connection string with the
    password in it gets pasted into an issue the first time the node is down.

    Checking for the *literal* password is not enough, and this test used to make exactly that
    mistake: the client holds the credentials pre-encoded, so a `repr` that leaked the base64
    blob would contain no plaintext password and sail past. Base64 is not encryption — anyone
    reading the log decodes it in a second.
    """
    client, _ = node
    text = repr(client)
    encoded = base64.b64encode(f"rpcuser:{PASSWORD}".encode()).decode()

    assert "127.0.0.1" in text
    assert PASSWORD not in text
    assert "rpcuser" not in text
    assert encoded not in text


def test_a_transport_error_message_carries_no_credentials():
    client = BitcoinRpc("127.0.0.1", 1, "rpcuser", PASSWORD, timeout=0.5)
    with pytest.raises(RpcTransportError) as exc:
        client.call("getblockcount")
    assert PASSWORD not in str(exc.value)
    assert PASSWORD not in repr(exc.value)
