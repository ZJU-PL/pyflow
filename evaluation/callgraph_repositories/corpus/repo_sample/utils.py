from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar
import time


T = TypeVar("T")


def retry(fn: Callable[[], T], retries: int = 3, delay: float = 0.01) -> T:
    last_error: Exception | None = None
    for _ in range(max(1, retries)):
        try:
            return fn()
        except Exception as exc:  # pragma: no cover - behavior-focused sample
            last_error = exc
            time.sleep(delay)
    assert last_error is not None
    raise last_error
