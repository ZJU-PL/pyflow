from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Generator


_request_context: ContextVar[dict[str, Any]] = ContextVar("request_context", default={})


@contextmanager
def request_context(**kwargs: Any) -> Generator[dict[str, Any], None, None]:
    token = _request_context.set(kwargs)
    try:
        yield kwargs
    finally:
        _request_context.reset(token)


class _Globals:
    def __getattr__(self, name: str) -> Any:
        ctx = _request_context.get()
        return ctx.get(name)

    def __setattr__(self, name: str, value: Any) -> None:
        ctx = _request_context.get()
        ctx[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        ctx = _request_context.get()
        return ctx.get(name, default)

    def set(self, name: str, value: Any) -> None:
        ctx = _request_context.get()
        ctx[name] = value

    def clear(self) -> None:
        _request_context.set({})


g = _Globals()


class RequestContext:
    def __init__(self, data: dict[str, Any] | None = None):
        self._data = data or {}
        self._token: Any = None

    def __enter__(self) -> RequestContext:
        self._token = _request_context.set(self._data)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        _request_context.reset(self._token)

    def get(self, name: str, default: Any = None) -> Any:
        return self._data.get(name, default)

    def set(self, name: str, value: Any) -> None:
        self._data[name] = value


class LocalProxy:
    def __init__(self, name: str):
        self._name = name

    def _get_current_object(self) -> Any:
        ctx = _request_context.get()
        return ctx.get(self._name)

    def __getattr__(self, name: str) -> Any:
        obj = self._get_current_object()
        if obj is None:
            raise AttributeError(f"'{self._name}' is not available in current context")
        return getattr(obj, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            obj = self._get_current_object()
            if obj is None:
                raise AttributeError(f"'{self._name}' is not available in current context")
            setattr(obj, name, value)
