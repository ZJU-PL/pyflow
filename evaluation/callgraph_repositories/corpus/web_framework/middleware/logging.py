from __future__ import annotations

import time
from typing import Any

from .base import Middleware
from ..request import Request
from ..response import Response


class LoggingMiddleware(Middleware):
    def __init__(self, app: Any | None = None, log_level: str = "INFO"):
        super().__init__(app)
        self.log_level = log_level
        self._logs: list[dict[str, Any]] = []

    def process_request(self, request: Request) -> Response | None:
        request._start_time = time.time()
        self._log("REQUEST", method=request.method, path=request.path)
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        duration = time.time() - getattr(request, "_start_time", time.time())
        self._log(
            "RESPONSE",
            method=request.method,
            path=request.path,
            status=response.status,
            duration_ms=round(duration * 1000, 2)
        )
        return response

    def _log(self, event: str, **kwargs: Any) -> None:
        entry = {"event": event, **kwargs}
        self._logs.append(entry)

    def get_logs(self) -> list[dict[str, Any]]:
        return list(self._logs)


class TimingMiddleware(Middleware):
    def __init__(self, app: Any | None = None, header_name: str = "X-Process-Time"):
        super().__init__(app)
        self.header_name = header_name

    def process_request(self, request: Request) -> Response | None:
        request._timing_start = time.time()
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        start = getattr(request, "_timing_start", time.time())
        duration = time.time() - start
        response.set_header(self.header_name, f"{duration:.6f}")
        return response


class CORSMiddleware(Middleware):
    def __init__(
        self,
        app: Any | None = None,
        allow_origins: str = "*",
        allow_methods: str = "GET,POST,PUT,DELETE,OPTIONS",
        allow_headers: str = "Content-Type,Authorization",
    ):
        super().__init__(app)
        self.allow_origins = allow_origins
        self.allow_methods = allow_methods
        self.allow_headers = allow_headers

    def process_request(self, request: Request) -> Response | None:
        if request.method == "OPTIONS":
            response = Response(status=204, body="")
            self._add_cors_headers(response)
            return response
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        self._add_cors_headers(response)
        return response

    def _add_cors_headers(self, response: Response) -> None:
        response.set_header("Access-Control-Allow-Origin", self.allow_origins)
        response.set_header("Access-Control-Allow-Methods", self.allow_methods)
        response.set_header("Access-Control-Allow-Headers", self.allow_headers)
