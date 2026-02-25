from __future__ import annotations

from typing import Any, Callable, TypeVar
from collections.abc import Generator

from .request import Request
from .response import Response
from .middleware.base import Middleware


F = TypeVar("F", bound=Callable[..., Any])


class RouteMeta(type):
    def __new__(mcs, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> type:
        cls = super().__new__(mcs, name, bases, namespace)
        routes: dict[str, Callable[..., Response]] = {}
        for key, value in namespace.items():
            if hasattr(value, "_route_path"):
                routes[value._route_path] = value
        cls._routes = routes
        return cls


class Router(metaclass=RouteMeta):
    _routes: dict[str, Callable[..., Response]] = {}

    def route(self, path: str) -> Callable[[F], F]:
        def decorator(fn: F) -> F:
            fn._route_path = path
            self._routes[path] = fn
            return fn
        return decorator

    def match(self, path: str) -> Callable[..., Response] | None:
        return self._routes.get(path)


class App:
    def __init__(self, name: str):
        self.name = name
        self._router = Router()
        self._middleware: list[Middleware] = []
        self._before_request: list[Callable[..., None]] = []
        self._after_request: list[Callable[..., Response, Response]] = []

    def route(self, path: str) -> Callable[[F], F]:
        return self._router.route(path)

    def use(self, middleware: Middleware) -> None:
        self._middleware.append(middleware)

    def before_request(self, fn: Callable[..., None]) -> Callable[..., None]:
        self._before_request.append(fn)
        return fn

    def after_request(self, fn: Callable[..., Response, Response]) -> Callable[..., Response, Response]:
        self._after_request.append(fn)
        return fn

    def handle(self, request: Request) -> Response:
        handler = self._router.match(request.path)
        if handler is None:
            return Response(status=404, body="Not Found")

        for middleware in self._middleware:
            result = middleware.process_request(request)
            if result is not None:
                return result

        for hook in self._before_request:
            hook(request)

        response = handler(request)

        for hook in reversed(self._after_request):
            response = hook(response)

        for middleware in reversed(self._middleware):
            response = middleware.process_response(request, response)

        return response

    def test_client(self) -> TestClient:
        return TestClient(self)


class TestClient:
    def __init__(self, app: App):
        self.app = app

    def get(self, path: str, headers: dict[str, str] | None = None) -> Response:
        request = Request(method="GET", path=path, headers=headers or {}, body=b"")
        return self.app.handle(request)

    def post(self, path: str, body: bytes = b"", headers: dict[str, str] | None = None) -> Response:
        request = Request(method="POST", path=path, headers=headers or {}, body=body)
        return self.app.handle(request)
