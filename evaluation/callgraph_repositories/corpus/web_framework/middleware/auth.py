from __future__ import annotations

from typing import Any, Callable

from .base import Middleware
from ..request import Request
from ..response import Response


class AuthMiddleware(Middleware):
    def __init__(
        self,
        app: Any | None = None,
        auth_header: str = "Authorization",
        prefix: str = "Bearer ",
    ):
        super().__init__(app)
        self.auth_header = auth_header
        self.prefix = prefix
        self._token_validators: list[Callable[[str], bool]] = []

    def add_validator(self, validator: Callable[[str], bool]) -> None:
        self._token_validators.append(validator)

    def process_request(self, request: Request) -> Response | None:
        token = self._extract_token(request)
        if token is None:
            return Response(status=401, body="Missing authentication token")
        
        for validator in self._token_validators:
            if not validator(token):
                return Response(status=403, body="Invalid token")
        
        request.user = self._get_user(token)
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        return response

    def _extract_token(self, request: Request) -> str | None:
        header = request.get_header(self.auth_header)
        if header is None:
            return None
        if not header.startswith(self.prefix):
            return None
        return header[len(self.prefix) :]

    def _get_user(self, token: str) -> dict[str, Any]:
        return {"token": token, "authenticated": True}


class RateLimitMiddleware(Middleware):
    def __init__(
        self,
        app: Any | None = None,
        requests_per_minute: int = 60,
        key_func: Callable[[Request], str] | None = None,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.key_func = key_func or (lambda r: r.get_header("X-Forwarded-For", r.path))
        self._requests: dict[str, list[float]] = {}

    def process_request(self, request: Request) -> Response | None:
        import time
        key = self.key_func(request)
        now = time.time()
        
        if key not in self._requests:
            self._requests[key] = []
        
        self._requests[key] = [t for t in self._requests[key] if now - t < 60]
        
        if len(self._requests[key]) >= self.requests_per_minute:
            return Response(status=429, body="Too Many Requests")
        
        self._requests[key].append(now)
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        return response


class SessionMiddleware(Middleware):
    def __init__(
        self,
        app: Any | None = None,
        secret_key: str = "secret",
        session_cookie: str = "session",
    ):
        super().__init__(app)
        self.secret_key = secret_key
        self.session_cookie = session_cookie

    def process_request(self, request: Request) -> Response | None:
        import base64
        import json
        
        cookie = request.get_header("Cookie", "")
        request.session = {}
        
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(f"{self.session_cookie}="):
                try:
                    data = base64.b64decode(part[len(self.session_cookie) + 1 :])
                    request.session = json.loads(data)
                except Exception:
                    request.session = {}
                break
        
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        import base64
        import json
        
        session = getattr(request, "session", {})
        if session:
            data = base64.b64encode(json.dumps(session).encode()).decode()
            existing = response.get_header("Set-Cookie", "")
            new_cookie = f"{self.session_cookie}={data}; Path=/; HttpOnly"
            if existing:
                response.set_header("Set-Cookie", f"{existing}, {new_cookie}")
            else:
                response.set_header("Set-Cookie", new_cookie)
        
        return response
