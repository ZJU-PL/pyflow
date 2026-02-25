from __future__ import annotations

from typing import Any, Generic, Iterator, TypeVar

from .base import Source, Transform, Sink, Configurable, Loggable, Validatable

T = TypeVar("T")
U = TypeVar("U")


class Pipeline(Source[T], Generic[T, U]):
    def __init__(self, source: Source[T], transforms: list[Transform[Any, Any]] | None = None):
        super().__init__(name=f"Pipeline({source.name})")
        self._source = source
        self._transforms = transforms or []

    def pipe(self, transform: Transform[Any, Any]) -> Pipeline[T, Any]:
        return Pipeline(self._source, self._transforms + [transform])

    def __iter__(self) -> Iterator[Any]:
        it: Iterator[Any] = iter(self._source)
        for transform in self._transforms:
            it = transform(it)
        return it

    def to(self, sink: Sink[Any]) -> Any:
        return sink.consume(iter(self))

    def collect(self) -> list[Any]:
        return list(self)

    def first(self) -> Any | None:
        for item in self:
            return item
        return None

    def take(self, n: int) -> list[Any]:
        import itertools
        return list(itertools.islice(self, n))

    def count(self) -> int:
        return sum(1 for _ in self)

    def reduce(self, func: Any, initial: Any = None) -> Any:
        import functools
        it = iter(self)
        if initial is None:
            initial = next(it)
        return functools.reduce(func, it, initial)


class BatchPipeline(Pipeline[T, U], Configurable, Loggable):
    def __init__(
        self,
        source: Source[T],
        batch_size: int = 100,
        transforms: list[Transform[Any, Any]] | None = None,
    ):
        super().__init__(source, transforms)
        Configurable.__init__(self, batch_size=batch_size)
        self.log(f"Created with batch_size={batch_size}")

    def __iter__(self) -> Iterator[list[Any]]:
        import itertools
        it: Iterator[Any] = iter(self._source)
        for transform in self._transforms:
            it = transform(it)
        
        while True:
            batch = list(itertools.islice(it, self.batch_size))
            if not batch:
                break
            self.log(f"Yielding batch of {len(batch)} items")
            yield batch


class ParallelPipeline(Pipeline[T, U]):
    def __init__(self, source: Source[T], workers: int = 4, transforms: list[Transform[Any, Any]] | None = None):
        super().__init__(source, transforms)
        self.workers = workers

    def __iter__(self) -> Iterator[Any]:
        import concurrent.futures
        import queue
        import threading

        it: Iterator[Any] = iter(self._source)
        for transform in self._transforms:
            it = transform(it)

        def producer(q: queue.Queue, iterator: Iterator[Any]) -> None:
            try:
                for item in iterator:
                    q.put(item)
            finally:
                for _ in range(self.workers):
                    q.put(None)

        q: queue.Queue = queue.Queue(maxsize=self.workers * 2)
        t = threading.Thread(target=producer, args=(q, it))
        t.start()

        while True:
            item = q.get()
            if item is None:
                self.workers -= 1
                if self.workers <= 0:
                    break
                continue
            yield item

        t.join()
