from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator, Sequence, TypeVar, Generic, overload

T = TypeVar("T", int, float)


@dataclass(frozen=True, slots=True)
class Shape:
    dims: tuple[int, ...]

    def __init__(self, *dims: int):
        object.__setattr__(self, "dims", tuple(dims))

    @property
    def ndim(self) -> int:
        return len(self.dims)

    @property
    def size(self) -> int:
        s = 1
        for d in self.dims:
            s *= d
        return s

    def __iter__(self) -> Iterator[int]:
        return iter(self.dims)

    def __len__(self) -> int:
        return len(self.dims)


class Tensor(Generic[T]):
    def __init__(self, data: Sequence[T] | None = None, shape: Shape | None = None):
        self._data: list[T] = list(data) if data else []
        self._shape = shape or Shape(len(self._data))
        self._grad: Tensor[T] | None = None
        self._requires_grad = False

    @property
    def shape(self) -> Shape:
        return self._shape

    @property
    def data(self) -> list[T]:
        return self._data

    @property
    def grad(self) -> Tensor[T] | None:
        return self._grad

    def requires_grad_(self, flag: bool = True) -> Tensor[T]:
        self._requires_grad = flag
        return self

    def backward(self, grad: Tensor[T] | None = None) -> None:
        if grad is not None:
            self._grad = grad

    @overload
    def __getitem__(self, idx: int) -> T: ...
    @overload
    def __getitem__(self, idx: slice) -> list[T]: ...
    def __getitem__(self, idx: int | slice) -> T | list[T]:
        return self._data[idx]

    def __setitem__(self, idx: int, value: T) -> None:
        self._data[idx] = value

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[T]:
        return iter(self._data)

    def __add__(self, other: Tensor[T]) -> Tensor[T]:
        return Tensor([a + b for a, b in zip(self._data, other._data)])

    def __mul__(self, other: Tensor[T]) -> Tensor[T]:
        return Tensor([a * b for a, b in zip(self._data, other._data)])

    def __matmul__(self, other: Tensor[T]) -> Tensor[T]:
        result = []
        for i in range(0, len(self._data), 2):
            for j in range(0, len(other._data), 2):
                s = 0
                for k in range(2):
                    s += self._data[i + k] * other._data[j + k]
                result.append(s)
        return Tensor(result)

    def reshape(self, *dims: int) -> Tensor[T]:
        new_shape = Shape(*dims)
        if new_shape.size != self._shape.size:
            raise ValueError(f"Cannot reshape {self._shape} to {new_shape}")
        t: Tensor[T] = Tensor(self._data, new_shape)
        t._requires_grad = self._requires_grad
        return t

    def tolist(self) -> list[T]:
        return list(self._data)

    @classmethod
    def zeros(cls, shape: Shape, dtype: type[T] = int) -> Tensor[T]:
        return cls([dtype(0) for _ in range(shape.size)], shape)

    @classmethod
    def ones(cls, shape: Shape, dtype: type[T] = int) -> Tensor[T]:
        return cls([dtype(1) for _ in range(shape.size)], shape)

    @classmethod
    def arange(cls, n: int, dtype: type[T] = int) -> Tensor[T]:
        return cls([dtype(i) for i in range(n)])
