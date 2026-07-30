"""Sink operations for the pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, TypeVar

from ..base import Sink, Configurable, Loggable, Validatable

T = TypeVar("T")


class ListSink(Sink[T], Configurable):
    def __init__(self, name: str | None = None):
        super().__init__(name=name or "ListSink")
        Configurable.__init__(self)
        self._result: list[T] = []

    def consume(self, source: Iterator[T]) -> list[T]:
        self._result = list(source)
        return self._result

    @property
    def result(self) -> list[T]:
        return self._result


class FileSink(Sink[str], Configurable, Loggable):
    def __init__(
        self,
        path: Path | str,
        mode: str = "w",
        encoding: str = "utf-8",
        name: str | None = None,
    ):
        super().__init__(name=name or f"FileSink({path})")
        Configurable.__init__(self, mode=mode, encoding=encoding)
        Loggable.__init__(self)
        self._path = Path(path)

    def consume(self, source: Iterator[str]) -> int:
        count = 0
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.log(f"Opening file: {self._path}")
        with self._path.open(self.mode, encoding=self.encoding) as f:
            for line in source:
                f.write(str(line) + "\n")
                count += 1
        self.log(f"Wrote {count} lines")
        return count


class CounterSink(Sink[T], Configurable, Loggable):
    def __init__(self, name: str | None = None):
        super().__init__(name=name or "CounterSink")
        Configurable.__init__(self)
        Loggable.__init__(self)
        self._count = 0

    def consume(self, source: Iterator[T]) -> int:
        self._count = sum(1 for _ in source)
        self.log(f"Counted {self._count} items")
        return self._count

    @property
    def count(self) -> int:
        return self._count


class JSONSink(Sink[Any], Configurable, Loggable):
    def __init__(
        self,
        path: Path | str,
        indent: int | None = 2,
        encoding: str = "utf-8",
        name: str | None = None,
    ):
        super().__init__(name=name or f"JSONSink({path})")
        Configurable.__init__(self, indent=indent, encoding=encoding)
        Loggable.__init__(self)
        self._path = Path(path)

    def consume(self, source: Iterator[Any]) -> int:
        items = list(source)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.log(f"Writing {len(items)} items to JSON")
        with self._path.open("w", encoding=self.encoding) as f:
            json.dump(items, f, indent=self.indent)
        return len(items)


class CSVSink(Sink[dict[str, Any]], Configurable, Loggable, Validatable):
    def __init__(
        self,
        path: Path | str,
        delimiter: str = ",",
        encoding: str = "utf-8",
        name: str | None = None,
    ):
        super().__init__(name=name or f"CSVSink({path})")
        Configurable.__init__(self, delimiter=delimiter, encoding=encoding)
        Loggable.__init__(self)
        self._path = Path(path)
        self._header: list[str] | None = None

    def validate(self, data: dict[str, Any]) -> bool:
        return isinstance(data, dict)

    def consume(self, source: Iterator[dict[str, Any]]) -> int:
        count = 0
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.log(f"Opening CSV for writing: {self._path}")
        with self._path.open("w", encoding=self.encoding) as f:
            for row in source:
                self.validate_or_raise(row)
                if self._header is None:
                    self._header = list(row.keys())
                    f.write(self.delimiter.join(self._header) + "\n")
                values = [str(row.get(h, "")) for h in self._header]
                f.write(self.delimiter.join(values) + "\n")
                count += 1
        self.log(f"Wrote {count} rows")
        return count


class DictSink(Sink[tuple[str, T]], Configurable):
    def __init__(self, name: str | None = None):
        super().__init__(name=name or "DictSink")
        Configurable.__init__(self)
        self._result: dict[str, T] = {}

    def consume(self, source: Iterator[tuple[str, T]]) -> dict[str, T]:
        self._result = dict(source)
        return self._result

    @property
    def result(self) -> dict[str, T]:
        return self._result


class PrintSink(Sink[T], Configurable, Loggable):
    def __init__(self, prefix: str = "", suffix: str = "", name: str | None = None):
        super().__init__(name=name or "PrintSink")
        Configurable.__init__(self, prefix=prefix, suffix=suffix)
        Loggable.__init__(self)
        self._count = 0

    def consume(self, source: Iterator[T]) -> int:
        self._count = 0
        for item in source:
            print(f"{self.prefix}{item}{self.suffix}")
            self._count += 1
        self.log(f"Printed {self._count} items")
        return self._count


class CollectN(Sink[T], Configurable, Loggable):
    def __init__(self, n: int, name: str | None = None):
        super().__init__(name=name or f"CollectN({n})")
        Configurable.__init__(self, n=n)
        Loggable.__init__(self)
        self._result: list[T] = []

    def consume(self, source: Iterator[T]) -> list[T]:
        import itertools
        self._result = list(itertools.islice(source, self.n))
        self.log(f"Collected {len(self._result)} items")
        return self._result

    @property
    def result(self) -> list[T]:
        return self._result
