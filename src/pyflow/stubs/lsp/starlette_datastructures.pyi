from typing import Any

class State:
    """Dynamic attributes are backed by an explicit state dictionary."""

    def __init__(self, state: dict[str, Any] | None = None) -> None: ...
    def __getattr__(self, key: str) -> Any: ...
