from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class Layer(ABC, Generic[T]):
    def __init__(self, name: str | None = None):
        self.name = name or self.__class__.__name__
        self._params: dict[str, Any] = {}
        self._training = True

    @abstractmethod
    def forward(self, x: T) -> T:
        pass

    @abstractmethod
    def backward(self, grad: T) -> T:
        pass

    def train(self) -> None:
        self._training = True

    def eval(self) -> None:
        self._training = False

    def parameters(self) -> dict[str, Any]:
        return self._params

    def __call__(self, x: T) -> T:
        return self.forward(x)

    def __repr__(self) -> str:
        params_str = ", ".join(f"{k}={v}" for k, v in self._params.items() if not k.startswith("_"))
        return f"{self.name}({params_str})" if params_str else f"{self.name}()"


class Parameter:
    def __init__(self, data: Any, requires_grad: bool = True):
        self.data = data
        self.requires_grad = requires_grad
        self.grad: Any = None

    def zero_grad(self) -> None:
        self.grad = None

    def __repr__(self) -> str:
        return f"Parameter(shape={getattr(self.data, 'shape', len(self.data))})"
