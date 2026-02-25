"""Minimal web framework with metaclasses, descriptors, and context managers."""

from .app import App, Router
from .request import Request
from .response import Response, JSONResponse, HTMLResponse
from .views import View, TemplateView
from .middleware.base import Middleware
from .middleware.logging import LoggingMiddleware
from .middleware.auth import AuthMiddleware
from .context import request_context, g

__all__ = [
    "App",
    "Router",
    "Request",
    "Response",
    "JSONResponse",
    "HTMLResponse",
    "View",
    "TemplateView",
    "Middleware",
    "LoggingMiddleware",
    "AuthMiddleware",
    "request_context",
    "g",
]
