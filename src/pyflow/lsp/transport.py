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
DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024


class ErrorCodes(IntEnum):
    """JSON-RPC 2.0 error codes."""

    ParseError = -32700
    InvalidRequest = -32600
    MethodNotFound = -32601
    InvalidParams = -32602
    InternalError = -32603
    RequestCancelled = -32800


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


def _create_message(payload: Any, *, content_type: Optional[str] = None) -> bytes:
    """Frame a JSON-RPC message with Content-Length headers.

    The ``Content-Type`` header is omitted by default (valid JSON-RPC)
    and may be set for protocol-specific needs (e.g. LSP).
    """
    body = json.dumps(
        payload, check_circular=False, ensure_ascii=False, separators=(",", ":")
    ).encode(ENCODING)
    header = f"Content-Length: {len(body)}\r\n"
    if content_type:
        header += f"Content-Type: {content_type}\r\n"
    header += "\r\n"
    return header.encode(ENCODING) + body


def _parse_content_length(line: bytes) -> Optional[int]:
    """Extract Content-Length value from a header line."""
    if not line.startswith(CONTENT_LENGTH):
        return None
    value = line[len(CONTENT_LENGTH) :].strip()
    try:
        return int(value)
    except ValueError:
        raise JsonRpcError(
            ErrorCodes.ParseError,
            f"Invalid Content-Length: {value.decode(ENCODING, errors='replace')}",
        )


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

    def __init__(
        self,
        *,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        max_in_flight: int = 64,
    ) -> None:
        self._reader: Optional[asyncio.StreamReader] = None
        self._handlers: dict[str, Callable[..., Any]] = {}
        self._max_message_size = max_message_size
        self._tasks: set[asyncio.Task[None]] = set()
        self._in_flight = asyncio.Semaphore(max_in_flight)
        self._send_lock: Optional[asyncio.Lock] = None
        self._request_tasks: dict[Any, asyncio.Task[Any]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, method: str, handler: Callable[[Any], Any]) -> None:
        """Register a handler for a JSON-RPC method.

        The handler receives the ``params`` value from the request and
        must return a JSON-serializable result (or raise ``JsonRpcError``).
        It may be a coroutine function or a plain function.
        """
        self._handlers[method] = handler

    def register_notification(self, method: str, handler: Callable[[Any], Any]) -> None:
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

            task = asyncio.create_task(self._dispatch(body, strict=True))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _read_message(self, reader: asyncio.StreamReader) -> Optional[Any]:
        """Read and parse one JSON-RPC message from the stream."""
        num_bytes: Optional[int] = None
        while True:
            line = await reader.readline()
            if not line:
                return None
            if not line.strip():
                break
            name, separator, value = line.partition(b":")
            if not separator:
                raise JsonRpcError(ErrorCodes.ParseError, "Malformed header")
            if name.strip().lower() == b"content-length":
                try:
                    num_bytes = int(value.strip())
                except ValueError as exc:
                    raise JsonRpcError(
                        ErrorCodes.ParseError,
                        "Invalid Content-Length: "
                        + value.strip().decode(ENCODING, errors="replace"),
                    ) from exc

        if num_bytes is None:
            raise JsonRpcError(ErrorCodes.ParseError, "Missing Content-Length header")
        if num_bytes < 0 or num_bytes > self._max_message_size:
            raise JsonRpcError(
                ErrorCodes.InvalidRequest,
                f"Content-Length must be between 0 and {self._max_message_size}",
            )

        raw = await reader.readexactly(num_bytes)
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JsonRpcError(ErrorCodes.ParseError, "Malformed JSON") from exc

    async def _dispatch(self, msg: Any, *, strict: bool = False) -> None:
        """Dispatch a parsed JSON-RPC message to its handler."""
        async with self._in_flight:
            if isinstance(msg, list):
                if not msg:
                    await self._send(
                        self._error(
                            None,
                            JsonRpcError(
                                ErrorCodes.InvalidRequest, "Empty JSON-RPC batch"
                            ),
                        )
                    )
                    return
                responses = await asyncio.gather(
                    *(self._dispatch_one(item, strict=strict) for item in msg)
                )
                payload = [response for response in responses if response is not None]
                if payload:
                    await self._send(payload)
                return

            request_id = (
                msg.get("id") if isinstance(msg, dict) and "id" in msg else None
            )
            has_request_id = isinstance(msg, dict) and "id" in msg
            task = asyncio.current_task()
            if has_request_id and task is not None:
                self._request_tasks[request_id] = task
            try:
                response = await self._dispatch_one(msg, strict=strict)
                if response is not None:
                    await self._send(response)
            except asyncio.CancelledError:
                if has_request_id:
                    await self._send(
                        self._error(
                            request_id,
                            JsonRpcError(
                                ErrorCodes.RequestCancelled, "Request cancelled"
                            ),
                        )
                    )
            finally:
                if has_request_id and self._request_tasks.get(request_id) is task:
                    self._request_tasks.pop(request_id, None)

    async def _dispatch_one(
        self, msg: Any, *, strict: bool = False
    ) -> Optional[dict[str, Any]]:
        if not isinstance(msg, dict):
            return self._error(
                None,
                JsonRpcError(ErrorCodes.InvalidRequest, "Request must be an object"),
            )

        has_id = "id" in msg
        msg_id = msg.get("id")
        if (strict or "jsonrpc" in msg) and msg.get("jsonrpc") != "2.0":
            return self._error(
                msg_id if has_id else None,
                JsonRpcError(ErrorCodes.InvalidRequest, "jsonrpc must be '2.0'"),
            )

        method = msg.get("method")
        if not isinstance(method, str) or not method:
            return self._error(
                msg_id if has_id else None,
                JsonRpcError(
                    ErrorCodes.InvalidRequest, "Missing or invalid 'method' field"
                ),
            )

        params = msg.get("params")
        if params is not None and not isinstance(params, (dict, list)):
            return (
                self._error(
                    msg_id,
                    JsonRpcError(
                        ErrorCodes.InvalidParams, "params must be an object or array"
                    ),
                )
                if has_id
                else None
            )

        if method == "$/cancelRequest":
            request_id = params.get("id") if isinstance(params, dict) else None
            task = self._request_tasks.get(request_id)
            if task is not None and task is not asyncio.current_task():
                task.cancel()
            return None

        handler = self._handlers.get(method)
        if handler is None:
            return (
                self._error(
                    msg_id,
                    JsonRpcError(
                        ErrorCodes.MethodNotFound, f"Method not found: {method}"
                    ),
                )
                if has_id
                else None
            )

        try:
            result = handler(params)
            if asyncio.iscoroutine(result):
                result = await result
        except JsonRpcError as exc:
            return self._error(msg_id, exc) if has_id else None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.exception("Handler %s failed", method)
            return (
                self._error(msg_id, JsonRpcError(ErrorCodes.InternalError, str(exc)))
                if has_id
                else None
            )

        return self._result(msg_id, result) if has_id else None

    async def _send(self, payload: Any) -> None:
        """Write a framed JSON-RPC message to stdout."""
        msg = _create_message(payload)
        if self._send_lock is None:
            self._send_lock = asyncio.Lock()
        async with self._send_lock:
            sys.stdout.buffer.write(msg)
            sys.stdout.buffer.flush()

    @staticmethod
    def _result(msg_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id: Any, err: JsonRpcError) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": err.to_dict()}


class JsonLineRpcServer(JsonRpcServer):
    """JSON-RPC server using newline-delimited UTF-8 messages.

    This is the stdio transport used by MCP.  LSP continues to use the
    ``Content-Length`` framed :class:`JsonRpcServer` above.
    """

    async def _read_message(self, reader: asyncio.StreamReader) -> Optional[Any]:
        raw = await reader.readline()
        if not raw:
            return None
        if len(raw) > self._max_message_size:
            raise JsonRpcError(ErrorCodes.InvalidRequest, "Message is too large")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JsonRpcError(ErrorCodes.ParseError, "Malformed JSON") from exc

    async def _send(self, payload: Any) -> None:
        body = (
            json.dumps(
                payload,
                check_circular=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode(ENCODING)
            + b"\n"
        )
        if self._send_lock is None:
            self._send_lock = asyncio.Lock()
        async with self._send_lock:
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.flush()
