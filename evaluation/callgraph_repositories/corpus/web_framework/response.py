from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json


@dataclass
class Response:
    status: int = 200
    headers: dict[str, str] | None = None
    body: str | bytes = ""

    @property
    def status_code(self) -> int:
        return self.status

    def set_header(self, name: str, value: str) -> None:
        if self.headers is None:
            self.headers = {}
        self.headers[name] = value

    def get_header(self, name: str, default: str | None = None) -> str | None:
        if self.headers is None:
            return default
        return self.headers.get(name, default)

    def to_bytes(self) -> bytes:
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return self.body


class JSONResponse(Response):
    def __init__(self, data: Any, status: int = 200, headers: dict[str, str] | None = None):
        body = json.dumps(data, indent=2)
        hdrs = headers or {}
        hdrs["Content-Type"] = "application/json"
        super().__init__(status=status, headers=hdrs, body=body)
        self.data = data


class HTMLResponse(Response):
    def __init__(self, html: str, status: int = 200, headers: dict[str, str] | None = None):
        hdrs = headers or {}
        hdrs["Content-Type"] = "text/html; charset=utf-8"
        super().__init__(status=status, headers=hdrs, body=html)


class RedirectResponse(Response):
    def __init__(self, location: str, status: int = 302):
        super().__init__(status=status, headers={"Location": location}, body="")


class StreamResponse:
    def __init__(self, status: int = 200, headers: dict[str, str] | None = None):
        self.status = status
        self.headers = headers or {}
        self._chunks: list[bytes] = []

    def write(self, data: str | bytes) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._chunks.append(data)

    def to_bytes(self) -> bytes:
        return b"".join(self._chunks)


class TemplateResponse(Response):
    def __init__(self, template: str, context: dict[str, Any], status: int = 200):
        body = self._render(template, context)
        super().__init__(
            status=status,
            headers={"Content-Type": "text/html; charset=utf-8"},
            body=body
        )
        self.template = template
        self.context = context

    def _render(self, template: str, context: dict[str, Any]) -> str:
        result = template
        for key, value in context.items():
            result = result.replace(f"{{{{{key}}}}}", str(value))
        return result
