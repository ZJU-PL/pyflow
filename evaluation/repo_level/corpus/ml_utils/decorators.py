from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, ParamSpec, cast

P = ParamSpec("P")
R = TypeVar("R")


def gradient(fn: Callable[P, R]) -> Callable[P, R]:
    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        return fn(*args, **kwargs)
    wrapper._has_gradient = True
    return wrapper


def memoize(maxsize: int = 128) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        cache: dict[tuple[Any, ...], R] = {}
        
        @wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            key = (args, tuple(sorted(kwargs.items())))
            if key in cache:
                return cache[key]
            result = fn(*args, **kwargs)
            if len(cache) >= maxsize:
                cache.pop(next(iter(cache)))
            cache[key] = result
            return result
        
        wrapper.cache = cache
        wrapper.cache_clear = lambda: cache.clear()
        return wrapper
    return decorator


def validate_input(*validators: Callable[[Any], bool]) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            for i, validator in enumerate(validators):
                if i < len(args):
                    if not validator(args[i]):
                        raise ValueError(f"Argument {i} failed validation")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


class cached_property:
    def __init__(self, fn: Callable[[Any], R]):
        self.fn = fn
        self.__doc__ = fn.__doc__

    def __get__(self, obj: Any, objtype: type | None = None) -> R:
        if obj is None:
            return cast(R, self)
        value = self.fn(obj)
        object.__setattr__(obj, self.fn.__name__, value)
        return value


def deprecated(message: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            import warnings
            warnings.warn(f"{fn.__name__} is deprecated: {message}", DeprecationWarning)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
