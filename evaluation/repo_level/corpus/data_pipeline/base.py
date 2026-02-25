from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, Iterator, TypeVar

T = TypeVar("T")
U = TypeVar("U")
V = TypeVar("V")


class Component(ABC):
    def __init__(self, name: str | None = None):
        self.name = name or self.__class__.__name__

    def __repr__(self) -> str:
        return f"{self.name}"


class Source(Component, Generic[T]):
    @abstractmethod
    def __iter__(self) -> Iterator[T]:
        pass

    def __or__(self, other: Transform[T, U]) -> Pipeline[T, U]:
        return Pipeline[T, U](self).pipe(other)


class Transform(Component, Generic[T, U]):
    @abstractmethod
    def __call__(self, source: Iterator[T]) -> Iterator[U]:
        pass

    def __or__(self, other: Transform[U, V]) -> Transform[T, V]:
        return _ComposedTransform(self, other)

    def __ror__(self, source: Source[T]) -> Pipeline[T, U]:
        return Pipeline[T, U](source).pipe(self)


class Sink(Component, Generic[T]):
    @abstractmethod
    def consume(self, source: Iterator[T]) -> Any:
        pass


class _ComposedTransform(Transform[T, V], Generic[T, U, V]):
    def __init__(self, first: Transform[T, U], second: Transform[U, V]):
        super().__init__(name=f"{first.name}|{second.name}")
        self._first = first
        self._second = second

    def __call__(self, source: Iterator[T]) -> Iterator[V]:
        return self._second(self._first(source))


class Configurable:
    def __init__(self, **kwargs: Any):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def get_config(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class Loggable:
    _log_level: str = "INFO"

    def log(self, message: str, level: str = "INFO") -> None:
        if self._should_log(level):
            print(f"[{level}] {self.__class__.__name__}: {message}")

    def _should_log(self, level: str) -> bool:
        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        return levels.index(level) >= levels.index(self._log_level)


class Validatable:
    def validate(self, data: Any) -> bool:
        return True

    def validate_or_raise(self, data: Any) -> None:
        if not self.validate(data):
            raise ValueError(f"Validation failed for {data!r}")
