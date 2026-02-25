from __future__ import annotations

from typing import Any

from .base import Layer, Parameter
from ..tensor import Tensor, Shape


class Conv2D(Layer[Tensor[float]]):
    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int | tuple[int, int],
        stride: int = 1,
        padding: int = 0,
        bias: bool = True,
        name: str | None = None,
    ):
        super().__init__(name)
        self.in_channels = in_channels
        self.out_channels = out_channels
        if isinstance(kernel_size, int):
            self.kernel_h = self.kernel_w = kernel_size
        else:
            self.kernel_h, self.kernel_w = kernel_size
        self.stride = stride
        self.padding = padding
        
        weight_size = out_channels * in_channels * self.kernel_h * self.kernel_w
        self._params["weight"] = Parameter([0.0] * weight_size)
        if bias:
            self._params["bias"] = Parameter([0.0] * out_channels)
        self._bias = bias

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        batch, in_c, in_h, in_w = x.shape.dims
        out_h = (in_h + 2 * self.padding - self.kernel_h) // self.stride + 1
        out_w = (in_w + 2 * self.padding - self.kernel_w) // self.stride + 1
        
        result = [0.0] * (batch * self.out_channels * out_h * out_w)
        return Tensor(result, Shape(batch, self.out_channels, out_h, out_w))

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        batch, _, out_h, out_w = grad.shape.dims
        in_h = (out_h - 1) * self.stride + self.kernel_h - 2 * self.padding
        in_w = (out_w - 1) * self.stride + self.kernel_w - 2 * self.padding
        
        result = [0.0] * (batch * self.in_channels * in_h * in_w)
        return Tensor(result, Shape(batch, self.in_channels, in_h, in_w))

    def extra_repr(self) -> str:
        return (
            f"in_channels={self.in_channels}, out_channels={self.out_channels}, "
            f"kernel_size=({self.kernel_h}, {self.kernel_w}), stride={self.stride}, padding={self.padding}"
        )
