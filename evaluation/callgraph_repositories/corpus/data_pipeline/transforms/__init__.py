"""Transform operations for the pipeline."""

from __future__ import annotations

import itertools
from collections import defaultdict
from typing import Any, Callable, Iterator, TypeVar

from ..base import Transform, Configurable, Loggable

T = TypeVar("T")
U = TypeVar("U")
K = TypeVar("K")


class Map(Transform[T, U], Configurable):
    def __init__(self, func: Callable[[T], U], name: str | None = None):
        super().__init__(name=name or f"Map({func.__name__})")
        Configurable.__init__(self)
        self._func = func

    def __call__(self, source: Iterator[T]) -> Iterator[U]:
        return map(self._func, source)


class Filter(Transform[T, T], Configurable):
    def __init__(self, predicate: Callable[[T], bool], name: str | None = None):
        super().__init__(name=name or f"Filter({predicate.__name__})")
        Configurable.__init__(self)
        self._predicate = predicate

    def __call__(self, source: Iterator[T]) -> Iterator[T]:
        return filter(self._predicate, source)


class FlatMap(Transform[T, U], Configurable):
    def __init__(self, func: Callable[[T], Iterator[U]], name: str | None = None):
        super().__init__(name=name or f"FlatMap({func.__name__})")
        Configurable.__init__(self)
        self._func = func

    def __call__(self, source: Iterator[T]) -> Iterator[U]:
        for item in source:
            yield from self._func(item)


class Take(Transform[T, T], Configurable):
    def __init__(self, n: int, name: str | None = None):
        super().__init__(name=name or f"Take({n})")
        Configurable.__init__(self, n=n)

    def __call__(self, source: Iterator[T]) -> Iterator[T]:
        return itertools.islice(source, self.n)


class Skip(Transform[T, T], Configurable):
    def __init__(self, n: int, name: str | None = None):
        super().__init__(name=name or f"Skip({n})")
        Configurable.__init__(self, n=n)

    def __call__(self, source: Iterator[T]) -> Iterator[T]:
        return itertools.islice(source, self.n, None)


class GroupBy(Transform[T, dict[K, list[T]]], Configurable, Loggable):
    def __init__(self, key_func: Callable[[T], K], name: str | None = None):
        super().__init__(name=name or f"GroupBy({key_func.__name__})")
        Configurable.__init__(self)
        Loggable.__init__(self)
        self._key_func = key_func

    def __call__(self, source: Iterator[T]) -> Iterator[dict[K, list[T]]]:
        groups: dict[K, list[T]] = defaultdict(list)
        for item in source:
            key = self._key_func(item)
            groups[key].append(item)
        self.log(f"Created {len(groups)} groups")
        yield dict(groups)


class Chunk(Transform[T, list[T]], Configurable):
    def __init__(self, size: int, name: str | None = None):
        super().__init__(name=name or f"Chunk({size})")
        Configurable.__init__(self, size=size)

    def __call__(self, source: Iterator[T]) -> Iterator[list[T]]:
        while True:
            chunk = list(itertools.islice(source, self.size))
            if not chunk:
                break
            yield chunk


class Sort(Transform[T, T], Configurable, Loggable):
    def __init__(self, key: Callable[[T], Any] | None = None, reverse: bool = False, name: str | None = None):
        super().__init__(name=name or "Sort")
        Configurable.__init__(self, reverse=reverse)
        Loggable.__init__(self)
        self._key = key

    def __call__(self, source: Iterator[T]) -> Iterator[T]:
        items = list(source)
        self.log(f"Sorting {len(items)} items")
        items.sort(key=self._key, reverse=self.reverse)
        return iter(items)


class Unique(Transform[T, T], Configurable):
    def __init__(self, key: Callable[[T], Any] | None = None, name: str | None = None):
        super().__init__(name=name or "Unique")
        Configurable.__init__(self)
        self._key = key

    def __call__(self, source: Iterator[T]) -> Iterator[T]:
        seen: set[Any] = set()
        for item in source:
            key = self._key(item) if self._key else item
            if key not in seen:
                seen.add(key)
                yield item


class ZipWith(Transform[T, tuple[T, U]], Configurable):
    def __init__(self, other: Iterator[U], name: str | None = None):
        super().__init__(name=name or "ZipWith")
        Configurable.__init__(self)
        self._other = other

    def __call__(self, source: Iterator[T]) -> Iterator[tuple[T, U]]:
        return zip(source, self._other)


class Enumerate(Transform[T, tuple[int, T]], Configurable):
    def __init__(self, start: int = 0, name: str | None = None):
        super().__init__(name=name or "Enumerate")
        Configurable.__init__(self, start=start)

    def __call__(self, source: Iterator[T]) -> Iterator[tuple[int, T]]:
        return enumerate(source, self.start)


class Tee(Transform[T, T], Configurable, Loggable):
    def __init__(self, n: int = 2, name: str | None = None):
        super().__init__(name=name or f"Tee({n})")
        Configurable.__init__(self, n=n)
        Loggable.__init__(self)

    def __call__(self, source: Iterator[T]) -> Iterator[T]:
        self.log(f"Creating {self.n} tee iterators")
        iterators = itertools.tee(source, self.n)
        return iterators[0]


class Batch(Transform[T, list[T]], Configurable, Loggable):
    def __init__(self, size: int, drop_last: bool = False, name: str | None = None):
        super().__init__(name=name or f"Batch({size})")
        Configurable.__init__(self, size=size, drop_last=drop_last)
        Loggable.__init__(self)

    def __call__(self, source: Iterator[T]) -> Iterator[list[T]]:
        batch: list[T] = []
        for item in source:
            batch.append(item)
            if len(batch) >= self.size:
                self.log(f"Yielding batch of {len(batch)}")
                yield batch
                batch = []
        if batch and not self.drop_last:
            self.log(f"Yielding final batch of {len(batch)}")
            yield batch


class Reduce(Transform[T, Any], Configurable):
    def __init__(self, func: Callable[[Any, T], Any], initial: Any = None, name: str | None = None):
        super().__init__(name=name or f"Reduce({func.__name__})")
        Configurable.__init__(self, initial=initial)
        self._func = func

    def __call__(self, source: Iterator[T]) -> Iterator[Any]:
        import functools
        if self.initial is not None:
            yield functools.reduce(self._func, source, self.initial)
        else:
            yield functools.reduce(self._func, source)
