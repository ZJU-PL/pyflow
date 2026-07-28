"""
JSON-RPC 2.0 transport for pyflow's analysis server.

Adapted from multilspy (MIT License, copyright Microsoft).
The original was an LSP *client*; this is adapted as a *server* that
reads JSON-RPC requests from stdin and writes responses to stdout.
"""

import asyncio
import json
import logging
import sys
from enum import IntEnum
from typing import Any, Callable, Optional

LOG = logging.getLogger(__name__)

CONTENT_LENGTH = b"Content-Length: "
ENCODING = "utf-8"


class ErrorCodes(IntEnum):
    """JSON-RPC 2.0 error codes."""
    ParseError = -32700
    InvalidRequest = -32600
    MethodNotFound = -32601
    InvalidParams = -32602
    InternalError = -32603


class JsonRpcError(Exception):
    """A JSON-RPC error that can be serialized to the wire format."""

    def __init__(self, code: ErrorCodes, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": str(self)}
        if self.data is not None:
            d["data"] = self.data
        return d


def _create_message(payload: dict[str, Any], *, content_type: Optional[str] = None) -> bytes:
    """Frame a JSON-RPC message with Content-Length headers.

    The ``Content-Type`` header is omitted by default (valid JSON-RPC)
    and may be set for protocol-specific needs (e.g. LSP).
    """
    body = json.dumps(payload, check_circular=False, ensure_ascii=False, separators=(",", ":")).encode(ENCODING)
    header = f"Content-Length: {len(body)}\r\n"
    if content_type:
        header += f"Content-Type: {content_type}\r\n"
    header += "\r\n"
    return header.encode(ENCODING) + body


def _parse_content_length(line: bytes) -> Optional[int]:
    """Extract Content-Length value from a header line."""
    if not line.startswith(CONTENT_LENGTH):
        return None
    value = line[len(CONTENT_LENGTH):].strip()
    try:
        return int(value)
    except ValueError:
        raise JsonRpcError(ErrorCodes.ParseError, f"Invalid Content-Length: {value}")


class JsonRpcServer:
    """JSON-RPC 2.0 server over stdio.

    Reads framed messages from stdin, dispatches to registered handlers,
    and writes responses to stdout. Supports both async and sync handlers.

    Usage::

        server = JsonRpcServer()
        server.register("method_name", handler_fn)

        asyncio.run(server.run())

    Each handler receives ``(params: Any) -> Any`` and returns a result
    that will be serialized as the JSON-RPC ``result`` field. Raise
    ``JsonRpcError`` to return an error response.
    """

    def __init__(self) -> None:
        self._reader: Optional[asyncio.StreamReader] = None
        self._handlers: dict[str, Callable[..., Any]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, method: str,
                 handler: Callable[[Any], Any]) -> None:
        """Register a handler for a JSON-RPC method.

        The handler receives the ``params`` value from the request and
        must return a JSON-serializable result (or raise ``JsonRpcError``).
        It may be a coroutine function or a plain function.
        """
        self._handlers[method] = handler

    def register_notification(self, method: str,
                              handler: Callable[[Any], None]) -> None:
        """Register a notification handler (no response sent)."""
        self._handlers[method] = handler

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run the server loop, reading from stdin until EOF."""
        if self._reader is None:
            self._reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(self._reader)
            loop = asyncio.get_running_loop()
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        reader = self._reader
        while not reader.at_eof():
            try:
                body = await self._read_message(reader)
            except (EOFError, ConnectionResetError, BrokenPipeError):
                break
            except JsonRpcError as exc:
                await self._send(self._error(None, exc))
                continue

            if body is None:
                continue

            asyncio.ensure_future(self._dispatch(body))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _read_message(self, reader: asyncio.StreamReader) -> Optional[dict[str, Any]]:
        """Read and parse one JSON-RPC message from the stream."""
        line = await reader.readline()
        if not line:
            return None
        num_bytes = _parse_content_length(line)
        if num_bytes is None:
            raise JsonRpcError(ErrorCodes.ParseError,
                               "Missing or invalid Content-Length header")

        while line and line.strip():
            line = await reader.readline()
            if not line:
                return None

        raw = await reader.readexactly(num_bytes)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise JsonRpcError(ErrorCodes.ParseError, "Malformed JSON")

    async def _dispatch(self, msg: dict[str, Any]) -> None:
        """Dispatch a parsed JSON-RPC message to its handler."""
        msg_id = msg.get("id")
        method = msg.get("method")

        if not method:
            await self._send(self._error(msg_id, JsonRpcError(
                ErrorCodes.InvalidRequest, "Missing 'method' field")))
            return

        handler = self._handlers.get(method)
        if handler is None:
            # Notifications don't get error responses
            if msg_id is not None:
                await self._send(self._error(msg_id, JsonRpcError(
                    ErrorCodes.MethodNotFound, f"Method not found: {method}")))
            return

        params = msg.get("params")

        try:
            result = handler(params)
            if asyncio.iscoroutine(result):
                result = await result
        except JsonRpcError as exc:
            if msg_id is not None:
                await self._send(self._error(msg_id, exc))
            return
        except Exception as exc:
            LOG.exception("Handler %s failed", method)
            if msg_id is not None:
                await self._send(self._error(
                    msg_id, JsonRpcError(ErrorCodes.InternalError, str(exc))))
            return

        # Notifications have no id — no response sent
        if msg_id is not None:
            await self._send(self._result(msg_id, result))

    async def _send(self, payload: dict[str, Any]) -> None:
        """Write a framed JSON-RPC message to stdout."""
        msg = _create_message(payload)
        sys.stdout.buffer.write(msg)
        sys.stdout.buffer.flush()

    @staticmethod
    def _result(msg_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id: Any, err: JsonRpcError) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": err.to_dict()}
