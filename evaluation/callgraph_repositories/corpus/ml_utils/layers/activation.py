from __future__ import annotations

import math
from typing import Any

from .base import Layer
from ..tensor import Tensor


class ReLU(Layer[Tensor[float]]):
    def __init__(self, name: str | None = None):
        super().__init__(name)

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        return Tensor([max(0.0, v) for v in x.data], x.shape)

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        return Tensor([g if v > 0 else 0.0 for g, v in zip(grad.data, self._input.data)], grad.shape)


class Softmax(Layer[Tensor[float]]):
    def __init__(self, dim: int = -1, name: str | None = None):
        super().__init__(name)
        self.dim = dim

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        max_val = max(x.data)
        exp_vals = [math.exp(v - max_val) for v in x.data]
        sum_exp = sum(exp_vals)
        self._output = [v / sum_exp for v in exp_vals]
        return Tensor(self._output, x.shape)

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        s = self._output
        result = []
        for i, g in enumerate(grad.data):
            total = 0.0
            for j, sj in enumerate(s):
                if i == j:
                    total += g * sj * (1 - sj)
                else:
                    total += -g * s[i] * sj
            result.append(total)
        return Tensor(result, grad.shape)


class Sigmoid(Layer[Tensor[float]]):
    def __init__(self, name: str | None = None):
        super().__init__(name)

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._output = [1.0 / (1.0 + math.exp(-v)) for v in x.data]
        return Tensor(self._output, x.shape)

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        return Tensor([g * s * (1 - s) for g, s in zip(grad.data, self._output)], grad.shape)


class Tanh(Layer[Tensor[float]]):
    def __init__(self, name: str | None = None):
        super().__init__(name)

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._output = [math.tanh(v) for v in x.data]
        return Tensor(self._output, x.shape)

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        return Tensor([g * (1 - t * t) for g, t in zip(grad.data, self._output)], grad.shape)


class GELU(Layer[Tensor[float]]):
    def __init__(self, name: str | None = None):
        super().__init__(name)

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        result = []
        for v in x.data:
            cdf = 0.5 * (1.0 + math.tanh(math.sqrt(2 / math.pi) * (v + 0.044715 * v ** 3)))
            result.append(v * cdf)
        return Tensor(result, x.shape)

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        x = self._input.data
        result = []
        for g, v in zip(grad.data, x):
            cdf = 0.5 * (1.0 + math.tanh(math.sqrt(2 / math.pi) * (v + 0.044715 * v ** 3)))
            pdf = 0.5 * math.sqrt(2 / math.pi) * (1 - math.tanh(math.sqrt(2 / math.pi) * (v + 0.044715 * v ** 3)) ** 2)
            result.append(g * (cdf + v * pdf))
        return Tensor(result, grad.shape)
