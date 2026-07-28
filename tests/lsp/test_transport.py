"""Tests for pyflow.lsp.transport — JSON-RPC message framing and dispatch."""

from __future__ import annotations

import asyncio
import json

import pytest

from pyflow.lsp.transport import (
    CONTENT_LENGTH,
    ENCODING,
    ErrorCodes,
    JsonRpcError,
    JsonRpcServer,
    _create_message,
    _parse_content_length,
)


# ---------------------------------------------------------------------------
# Message framing helpers
# ---------------------------------------------------------------------------


def test_create_message_has_content_length_header():
    payload = {"jsonrpc": "2.0", "id": 1, "result": "ok"}
    msg = _create_message(payload)
    header, _, body = msg.partition(b"\r\n\r\n")
    assert header.startswith(b"Content-Length: ")
    assert b"Content-Type" not in header  # omitted by default


def test_create_message_length_matches_body():
    payload = {"jsonrpc": "2.0", "id": 1, "result": "hello"}
    msg = _create_message(payload)
    _, rest = msg.split(b"\r\n\r\n", 1)
    decoded = json.loads(rest)
    assert decoded == payload


def test_create_message_minimal_separators():
    """Ensures separators=(',', ':') for compact output."""
    payload = {"a": 1, "b": 2}
    msg = _create_message(payload)
    _, body = msg.split(b"\r\n\r\n", 1)
    assert b", " not in body  # no extra whitespace


def test_parse_content_length_valid():
    line = b"Content-Length: 42\r\n"
    assert _parse_content_length(line) == 42


def test_parse_content_length_returns_none_for_non_matching_line():
    assert _parse_content_length(b"Other: header\r\n") is None


def test_parse_content_length_invalid_raises():
    with pytest.raises(JsonRpcError) as exc_info:
        _parse_content_length(b"Content-Length: abc\r\n")
    assert exc_info.value.code == ErrorCodes.ParseError


# ---------------------------------------------------------------------------
# ErrorCodes and JsonRpcError
# ---------------------------------------------------------------------------


class TestErrorCodes:
    def test_parse_error(self):
        assert ErrorCodes.ParseError == -32700

    def test_invalid_request(self):
        assert ErrorCodes.InvalidRequest == -32600

    def test_method_not_found(self):
        assert ErrorCodes.MethodNotFound == -32601

    def test_invalid_params(self):
        assert ErrorCodes.InvalidParams == -32602

    def test_internal_error(self):
        assert ErrorCodes.InternalError == -32603


class TestJsonRpcError:
    def test_to_dict_includes_code_and_message(self):
        err = JsonRpcError(ErrorCodes.ParseError, "bad json")
        d = err.to_dict()
        assert d["code"] == ErrorCodes.ParseError
        assert d["message"] == "bad json"

    def test_to_dict_includes_optional_data(self):
        err = JsonRpcError(ErrorCodes.InternalError, "oops", data={"detail": "x"})
        d = err.to_dict()
        assert d["data"] == {"detail": "x"}

    def test_to_dict_omits_data_when_none(self):
        err = JsonRpcError(ErrorCodes.MethodNotFound, "nope")
        d = err.to_dict()
        assert "data" not in d


# ---------------------------------------------------------------------------
# JsonRpcServer helper
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


@pytest.fixture
def server():
    return JsonRpcServer()


class TestJsonRpcServer:
    def test_dispatch_calls_registered_handler(self, server):
        calls = []

        def my_handler(params):
            calls.append(params)
            return "ok"

        server.register("test/method", my_handler)
        _run(server._dispatch(
            {"id": 1, "method": "test/method", "params": {"x": 1}}))
        assert calls == [{"x": 1}]

    def test_dispatch_returns_result_with_id(self, server):
        server.register("ping", lambda p: "pong")
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch({"id": 42, "method": "ping", "params": None}))
        assert len(sent) == 1
        assert sent[0] == {"jsonrpc": "2.0", "id": 42, "result": "pong"}

    def test_dispatch_sends_no_response_for_notification(self, server):
        server.register("notify", lambda p: "should-not-send")
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch({"method": "notify", "params": None}))
        assert sent == []

    def test_dispatch_method_not_found(self, server):
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch({"id": 1, "method": "unknown", "params": None}))
        assert len(sent) == 1
        assert "error" in sent[0]
        assert sent[0]["error"]["code"] == ErrorCodes.MethodNotFound

    def test_dispatch_method_not_found_no_response_for_notification(self, server):
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch({"method": "unknown", "params": None}))
        assert sent == []

    def test_dispatch_missing_method_field(self, server):
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch({"id": 1, "params": None}))
        assert len(sent) == 1
        assert sent[0]["error"]["code"] == ErrorCodes.InvalidRequest

    def test_dispatch_async_handler(self, server):
        async def async_handler(params):
            return "async-result"

        server.register("async/method", async_handler)
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch(
            {"id": 1, "method": "async/method", "params": None}))
        assert sent[0]["result"] == "async-result"

    def test_dispatch_handler_raises_json_rpc_error(self, server):
        def failing_handler(params):
            raise JsonRpcError(ErrorCodes.InternalError, "boom")

        server.register("fails", failing_handler)
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch({"id": 1, "method": "fails", "params": None}))
        assert sent[0]["error"]["code"] == ErrorCodes.InternalError
        assert sent[0]["error"]["message"] == "boom"

    def test_dispatch_handler_raises_unexpected_error(self, server):
        def exploding_handler(params):
            raise ValueError("unexpected")

        server.register("explodes", exploding_handler)
        sent = []

        async def capture_send(payload):
            sent.append(payload)

        server._send = capture_send  # type: ignore[assignment]
        _run(server._dispatch(
            {"id": 1, "method": "explodes", "params": None}))
        assert sent[0]["error"]["code"] == ErrorCodes.InternalError

    # ------------------------------------------------------------------
    # _result / _error static helpers
    # ------------------------------------------------------------------

    def test_result_format(self):
        r = JsonRpcServer._result(1, {"data": 42})
        assert r == {"jsonrpc": "2.0", "id": 1, "result": {"data": 42}}

    def test_error_format(self):
        err = JsonRpcError(ErrorCodes.ParseError, "bad")
        r = JsonRpcServer._error(1, err)
        assert r["jsonrpc"] == "2.0"
        assert r["id"] == 1
        assert r["error"]["code"] == ErrorCodes.ParseError
        assert r["error"]["message"] == "bad"

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def test_register_adds_handler(self, server):
        def h(p):
            pass
        server.register("x", h)
        assert server._handlers["x"] is h

    def test_register_notification_adds_handler(self, server):
        def h(p):
            pass
        server.register_notification("y", h)
        assert server._handlers["y"] is h
