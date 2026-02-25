from __future__ import annotations

from typing import Any

from .base import Layer, Parameter
from ..tensor import Tensor


class Dense(Layer[Tensor[float]]):
    def __init__(self, in_features: int, out_features: int, bias: bool = True, name: str | None = None):
        super().__init__(name)
        self.in_features = in_features
        self.out_features = out_features
        self._params["weight"] = Parameter([0.0] * (in_features * out_features))
        if bias:
            self._params["bias"] = Parameter([0.0] * out_features)
        self._bias = bias

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        w = self._params["weight"].data
        b = self._params.get("bias")
        result = []
        for i in range(self.out_features):
            s = 0.0
            for j in range(self.in_features):
                s += x.data[j] * w[i * self.in_features + j]
            if b is not None:
                s += b.data[i]
            result.append(s)
        return Tensor(result, Shape(self.out_features))

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        w = self._params["weight"]
        if w.requires_grad:
            w.grad = [0.0] * len(w.data)
            for i in range(self.out_features):
                for j in range(self.in_features):
                    w.grad[i * self.in_features + j] = grad.data[i] * self._input.data[j]
        if self._bias and "bias" in self._params:
            b = self._params["bias"]
            if b.requires_grad:
                b.grad = list(grad.data)
        
        input_grad = [0.0] * self.in_features
        for j in range(self.in_features):
            for i in range(self.out_features):
                input_grad[j] += grad.data[i] * w.data[i * self.in_features + j]
        return Tensor(input_grad, Shape(self.in_features))

    def extra_repr(self) -> str:
        return f"in_features={self.in_features}, out_features={self.out_features}, bias={self._bias}"


from ..tensor import Shape
