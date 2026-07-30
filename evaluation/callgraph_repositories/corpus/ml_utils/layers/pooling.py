from __future__ import annotations

from typing import Any

from .base import Layer
from ..tensor import Tensor, Shape


class MaxPool2D(Layer[Tensor[float]]):
    def __init__(self, kernel_size: int | tuple[int, int], stride: int | None = None, name: str | None = None):
        super().__init__(name)
        if isinstance(kernel_size, int):
            self.kernel_h = self.kernel_w = kernel_size
        else:
            self.kernel_h, self.kernel_w = kernel_size
        self.stride = stride if stride is not None else self.kernel_h

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        batch, channels, in_h, in_w = x.shape.dims
        out_h = (in_h - self.kernel_h) // self.stride + 1
        out_w = (in_w - self.kernel_w) // self.stride + 1
        
        result = []
        for b in range(batch):
            for c in range(channels):
                for oh in range(out_h):
                    for ow in range(out_w):
                        max_val = float("-inf")
                        for kh in range(self.kernel_h):
                            for kw in range(self.kernel_w):
                                ih = oh * self.stride + kh
                                iw = ow * self.stride + kw
                                idx = b * channels * in_h * in_w + c * in_h * in_w + ih * in_w + iw
                                if idx < len(x.data):
                                    max_val = max(max_val, x.data[idx])
                        result.append(max_val)
        
        return Tensor(result, Shape(batch, channels, out_h, out_w))

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        x = self._input
        batch, channels, in_h, in_w = x.shape.dims
        _, _, out_h, out_w = grad.shape.dims
        
        result = [0.0] * len(x.data)
        grad_idx = 0
        for b in range(batch):
            for c in range(channels):
                for oh in range(out_h):
                    for ow in range(out_w):
                        max_val = float("-inf")
                        max_idx = -1
                        for kh in range(self.kernel_h):
                            for kw in range(self.kernel_w):
                                ih = oh * self.stride + kh
                                iw = ow * self.stride + kw
                                idx = b * channels * in_h * in_w + c * in_h * in_w + ih * in_w + iw
                                if idx < len(x.data) and x.data[idx] > max_val:
                                    max_val = x.data[idx]
                                    max_idx = idx
                        if max_idx >= 0 and grad_idx < len(grad.data):
                            result[max_idx] = grad.data[grad_idx]
                        grad_idx += 1
        
        return Tensor(result, x.shape)


class AvgPool2D(Layer[Tensor[float]]):
    def __init__(self, kernel_size: int | tuple[int, int], stride: int | None = None, name: str | None = None):
        super().__init__(name)
        if isinstance(kernel_size, int):
            self.kernel_h = self.kernel_w = kernel_size
        else:
            self.kernel_h, self.kernel_w = kernel_size
        self.stride = stride if stride is not None else self.kernel_h
        self._pool_size = self.kernel_h * self.kernel_w

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        batch, channels, in_h, in_w = x.shape.dims
        out_h = (in_h - self.kernel_h) // self.stride + 1
        out_w = (in_w - self.kernel_w) // self.stride + 1
        
        result = []
        for b in range(batch):
            for c in range(channels):
                for oh in range(out_h):
                    for ow in range(out_w):
                        total = 0.0
                        for kh in range(self.kernel_h):
                            for kw in range(self.kernel_w):
                                ih = oh * self.stride + kh
                                iw = ow * self.stride + kw
                                idx = b * channels * in_h * in_w + c * in_h * in_w + ih * in_w + iw
                                if idx < len(x.data):
                                    total += x.data[idx]
                        result.append(total / self._pool_size)
        
        return Tensor(result, Shape(batch, channels, out_h, out_w))

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        x = self._input
        batch, channels, in_h, in_w = x.shape.dims
        _, _, out_h, out_w = grad.shape.dims
        
        result = [0.0] * len(x.data)
        grad_idx = 0
        for b in range(batch):
            for c in range(channels):
                for oh in range(out_h):
                    for ow in range(out_w):
                        g = grad.data[grad_idx] / self._pool_size if grad_idx < len(grad.data) else 0.0
                        for kh in range(self.kernel_h):
                            for kw in range(self.kernel_w):
                                ih = oh * self.stride + kh
                                iw = ow * self.stride + kw
                                idx = b * channels * in_h * in_w + c * in_h * in_w + ih * in_w + iw
                                if idx < len(result):
                                    result[idx] += g
                        grad_idx += 1
        
        return Tensor(result, x.shape)


class AdaptiveAvgPool2D(Layer[Tensor[float]]):
    def __init__(self, output_size: int | tuple[int, int], name: str | None = None):
        super().__init__(name)
        if isinstance(output_size, int):
            self.out_h = self.out_w = output_size
        else:
            self.out_h, self.out_w = output_size

    def forward(self, x: Tensor[float]) -> Tensor[float]:
        self._input = x
        batch, channels, in_h, in_w = x.shape.dims
        
        stride_h = in_h // self.out_h
        stride_w = in_w // self.out_w
        kernel_h = in_h - (self.out_h - 1) * stride_h
        kernel_w = in_w - (self.out_w - 1) * stride_w
        
        result = []
        for b in range(batch):
            for c in range(channels):
                for oh in range(self.out_h):
                    for ow in range(self.out_w):
                        start_h = oh * stride_h
                        start_w = ow * stride_w
                        total = 0.0
                        count = 0
                        for kh in range(kernel_h):
                            for kw in range(kernel_w):
                                ih = start_h + kh
                                iw = start_w + kw
                                if ih < in_h and iw < in_w:
                                    idx = b * channels * in_h * in_w + c * in_h * in_w + ih * in_w + iw
                                    if idx < len(x.data):
                                        total += x.data[idx]
                                        count += 1
                        result.append(total / max(count, 1))
        
        return Tensor(result, Shape(batch, channels, self.out_h, self.out_w))

    def backward(self, grad: Tensor[float]) -> Tensor[float]:
        return self._input
