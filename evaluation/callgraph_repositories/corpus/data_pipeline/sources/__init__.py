"""Data sources for the pipeline."""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from ..base import Source, Configurable, Loggable, Validatable

T = TypeVar("T")


class ListSource(Source[T], Configurable):
    def __init__(self, data: list[T], name: str | None = None):
        super().__init__(name=name or "ListSource")
        Configurable.__init__(self)
        self._data = data

    def __iter__(self) -> Iterator[T]:
        return iter(self._data)


class FileSource(Source[str], Configurable, Loggable):
    def __init__(
        self,
        path: Path | str,
        encoding: str = "utf-8",
        skip_empty: bool = True,
        name: str | None = None,
    ):
        super().__init__(name=name or f"FileSource({path})")
        Configurable.__init__(self, encoding=encoding, skip_empty=skip_empty)
        Loggable.__init__(self)
        self._path = Path(path)

    def __iter__(self) -> Iterator[str]:
        self.log(f"Opening file: {self._path}")
        with self._path.open("r", encoding=self.encoding) as f:
            for line in f:
                line = line.rstrip("\n\r")
                if self.skip_empty and not line:
                    continue
                yield line


class GeneratorSource(Source[T], Configurable):
    def __init__(self, generator: Callable[[], Iterator[T]], name: str | None = None):
        super().__init__(name=name or "GeneratorSource")
        Configurable.__init__(self)
        self._generator = generator

    def __iter__(self) -> Iterator[T]:
        return self._generator()


class RangeSource(Source[int], Configurable):
    def __init__(self, start: int, stop: int | None = None, step: int = 1, name: str | None = None):
        super().__init__(name=name or "RangeSource")
        Configurable.__init__(self, start=start, stop=stop, step=step)
        if stop is None:
            self._start, self._stop = 0, start
        else:
            self._start, self._stop = start, stop
        self._step = step

    def __iter__(self) -> Iterator[int]:
        return iter(range(self._start, self._stop, self._step))


class RepeatSource(Source[T], Configurable):
    def __init__(self, value: T, times: int | None = None, name: str | None = None):
        super().__init__(name=name or "RepeatSource")
        Configurable.__init__(self, times=times)
        self._value = value
        self._times = times

    def __iter__() -> Iterator[T]:
        raise NotImplementedError("Instance method needed")

    def __iter__(self) -> Iterator[T]:
        if self._times is None:
            return itertools.repeat(self._value)
        return itertools.repeat(self._value, self._times)


class CycleSource(Source[T], Configurable):
    def __init__(self, data: list[T], name: str | None = None):
        super().__init__(name=name or "CycleSource")
        Configurable.__init__(self)
        self._data = data

    def __iter__(self) -> Iterator[T]:
        return itertools.cycle(self._data)


class ChainSource(Source[T], Configurable):
    def __init__(self, sources: list[Source[T]], name: str | None = None):
        super().__init__(name=name or "ChainSource")
        Configurable.__init__(self)
        self._sources = sources

    def __iter__(self) -> Iterator[T]:
        return itertools.chain.from_iterable(self._sources)


class CSVSource(Source[dict[str, str]], Configurable, Loggable, Validatable):
    def __init__(
        self,
        path: Path | str,
        delimiter: str = ",",
        has_header: bool = True,
        encoding: str = "utf-8",
        name: str | None = None,
    ):
        super().__init__(name=name or f"CSVSource({path})")
        Configurable.__init__(self, delimiter=delimiter, has_header=has_header, encoding=encoding)
        Loggable.__init__(self)
        self._path = Path(path)

    def validate(self, data: dict[str, str]) -> bool:
        return isinstance(data, dict) and len(data) > 0

    def __iter__(self) -> Iterator[dict[str, str]]:
        self.log(f"Opening CSV: {self._path}")
        with self._path.open("r", encoding=self.encoding) as f:
            header: list[str] | None = None
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                values = line.split(self.delimiter)
                if header is None:
                    if self.has_header:
                        header = values
                        continue
                    header = [f"col{i}" for i in range(len(values))]
                row = dict(zip(header, values))
                self.validate_or_raise(row)
                yield row
