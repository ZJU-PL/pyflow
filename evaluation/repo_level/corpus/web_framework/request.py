from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from io import BytesIO


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    _json: dict[str, Any] | None = field(default=None, repr=False)
    _form: dict[str, str] | None = field(default=None, repr=False)

    @property
    def json(self) -> dict[str, Any]:
        if self._json is None:
            import json
            self._json = json.loads(self.body.decode("utf-8"))
        return self._json

    @property
    def form(self) -> dict[str, str]:
        if self._form is None:
            self._form = {}
            if self.body:
                for pair in self.body.decode("utf-8").split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        self._form[k] = v
        return self._form

    @property
    def content_type(self) -> str | None:
        return self.headers.get("Content-Type")

    @property
    def content_length(self) -> int:
        return len(self.body)

    @property
    def query_string(self) -> str:
        if "?" in self.path:
            return self.path.split("?", 1)[1]
        return ""

    @property
    def query_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.query_string:
            for pair in self.query_string.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        return params

    @property
    def path_without_query(self) -> str:
        return self.path.split("?")[0]

    def get_header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)
