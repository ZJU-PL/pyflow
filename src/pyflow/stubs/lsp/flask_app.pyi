"""Fallback editor contracts; real workspace/installed source takes precedence."""

from typing import Any, Callable

class Flask:
    config: dict[str, Any]
    blueprints: dict[str, Any]
    def route(self, rule: str, **options: Any) -> Callable[..., Any]: ...
