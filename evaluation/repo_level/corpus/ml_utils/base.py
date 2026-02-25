from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol, TypeVar, runtime_checkable

T = TypeVar("T", covariant=True)


@runtime_checkable
class Serializable(Protocol[T]):
    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> T: ...


class Model(ABC):
    def __init__(self, name: str):
        self.name = name
        self._params: dict[str, Any] = {}
        self._compiled = False

    @abstractmethod
    def forward(self, x: Any) -> Any:
        pass

    @abstractmethod
    def backward(self, grad: Any) -> Any:
        pass

    def compile(self, optimizer: str = "sgd", learning_rate: float = 0.01) -> None:
        self._compiled = True
        self._optimizer = optimizer
        self._lr = learning_rate

    def save(self, path: Path) -> None:
        import json
        data = {"name": self.name, "params": self._params}
        path.write_text(json.dumps(data))

    def load(self, path: Path) -> None:
        import json
        data = json.loads(path.read_text())
        self.name = data["name"]
        self._params = data["params"]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"


class Sequential(Model):
    def __init__(self, layers: list[Any] | None = None):
        super().__init__("sequential")
        self._layers = layers or []

    def add(self, layer: Any) -> None:
        self._layers.append(layer)

    def forward(self, x: Any) -> Any:
        out = x
        for layer in self._layers:
            out = layer.forward(out)
        return out

    def backward(self, grad: Any) -> Any:
        g = grad
        for layer in reversed(self._layers):
            g = layer.backward(g)
        return g
