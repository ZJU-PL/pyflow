from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..request import Request
from ..response import Response


class Middleware(ABC):
    def __init__(self, app: Any | None = None):
        self.app = app

    @abstractmethod
    def process_request(self, request: Request) -> Response | None:
        pass

    @abstractmethod
    def process_response(self, request: Request, response: Response) -> Response:
        pass

    def __call__(self, request: Request) -> Response:
        result = self.process_request(request)
        if result is not None:
            return result
        if self.app is not None:
            response = self.app.handle(request)
        else:
            response = Response(status=500, body="No app configured")
        return self.process_response(request, response)


class MiddlewareStack:
    def __init__(self):
        self._middleware: list[Middleware] = []

    def add(self, middleware: Middleware) -> None:
        self._middleware.append(middleware)

    def apply(self, request: Request, final_handler: Any) -> Response:
        def build_chain(index: int) -> Any:
            if index >= len(self._middleware):
                return final_handler
            
            mw = self._middleware[index]
            
            def handler(req: Request) -> Response:
                result = mw.process_request(req)
                if result is not None:
                    return result
                inner = build_chain(index + 1)
                response = inner(req)
                return mw.process_response(req, response)
            
            return handler
        
        chain = build_chain(0)
        return chain(request)
