"""
PyTorch Contract Registry and Utilities

This module provides the global registry for PyTorch contracts
and utilities for contract registration.
"""

from typing import Optional, List, Dict, Any, Callable
from functools import wraps
import math

from ..intervals import Interval
from ..contracts import (
    LibraryContract, FunctionContract, MethodContract, 
    ModuleContract, PropertyContract, ContractRegistry,
    ContractBuilder, Precondition, Postcondition, Invariant,
    SideEffect, contract
)
from ..abstract_values import Shape, DType, Device


# Global registry for PyTorch contracts
TORCH_REGISTRY = ContractRegistry()


def register_all_torch_contracts(registry: ContractRegistry = None) -> ContractRegistry:
    """
    Register all PyTorch contracts.
    
    Args:
        registry: Registry to use. If None, uses TORCH_REGISTRY.
        
    Returns:
        The registry with all contracts registered.
    """
    if registry is None:
        registry = TORCH_REGISTRY
    
    from .core import register_core_contracts
    from .tensor import register_tensor_contracts
    from .nn_functional import register_nn_functional_contracts
    from .nn_modules import register_nn_module_contracts
    from .linalg import register_linalg_contracts
    from .fft import register_fft_contracts
    from .special import register_special_contracts
    from .distributions import register_distribution_contracts
    from .optim import register_optim_contracts
    from .autograd import register_autograd_contracts
    from .cuda import register_cuda_contracts
    from .sparse import register_sparse_contracts
    from .distributed import register_distributed_contracts
    from .jit import register_jit_contracts
    from .data import register_data_contracts
    from .quantization import register_quantization_contracts
    from .onnx import register_onnx_contracts
    from .profiler import register_profiler_contracts
    from .utils import register_utils_contracts
    from .backends import register_backends_contracts
    from .export_compile import register_export_compile_contracts
    from .hub_package import register_hub_package_contracts
    from .amp import register_amp_contracts
    from .experimental import register_experimental_contracts
    from .accelerators import register_accelerator_contracts
    
    # Register all contract categories
    register_core_contracts(registry)
    register_tensor_contracts(registry)
    register_nn_functional_contracts(registry)
    register_nn_module_contracts(registry)
    register_linalg_contracts(registry)
    register_fft_contracts(registry)
    register_special_contracts(registry)
    register_distribution_contracts(registry)
    register_optim_contracts(registry)
    register_autograd_contracts(registry)
    register_cuda_contracts(registry)
    register_sparse_contracts(registry)
    register_distributed_contracts(registry)
    register_jit_contracts(registry)
    register_data_contracts(registry)
    register_quantization_contracts(registry)
    register_onnx_contracts(registry)
    register_profiler_contracts(registry)
    register_amp_contracts(registry)
    register_experimental_contracts(registry)
    register_accelerator_contracts(registry)
    register_utils_contracts(registry)
    register_backends_contracts(registry)
    register_export_compile_contracts(registry)
    register_hub_package_contracts(registry)
    
    return registry


def get_torch_contract(module: str, name: str) -> Optional[LibraryContract]:
    """Get a PyTorch contract from the global registry."""
    # Ensure contracts are registered
    if len(TORCH_REGISTRY) == 0:
        register_all_torch_contracts(TORCH_REGISTRY)
    
    return TORCH_REGISTRY.get(module, name)


# =============================================================================
# Registration Decorators
# =============================================================================

def torch_contract(module: str, name: str = None):
    """
    Decorator for registering a contract creation function.
    
    Usage:
        @torch_contract("torch", "sigmoid")
        def sigmoid_contract():
            return interval_contract("sigmoid", "torch", 0, 1)
    """
    def decorator(func: Callable[[], LibraryContract]):
        contract = func()
        if name:
            contract.name = name
        TORCH_REGISTRY.register(contract)
        return func
    return decorator


def bulk_register(contracts: List[LibraryContract], 
                  registry: ContractRegistry = None) -> None:
    """Register multiple contracts at once."""
    if registry is None:
        registry = TORCH_REGISTRY
    
    for c in contracts:
        registry.register(c)


# =============================================================================
# Common Interval Functions
# =============================================================================

def clamp_interval(input_interval: Interval, min_val: float, max_val: float) -> Interval:
    """Compute interval after clamping."""
    return Interval(
        max(min_val, input_interval.lo),
        min(max_val, input_interval.hi)
    )


def softmax_interval() -> Interval:
    """Softmax output is in (0, 1) for each element."""
    return Interval(0.0, 1.0)


def log_softmax_interval() -> Interval:
    """Log-softmax output is in (-∞, 0]."""
    return Interval(float('-inf'), 0.0)


# =============================================================================
# Shape Computation Helpers
# =============================================================================

def broadcast_shapes(shapes: List[Shape]) -> Shape:
    """Compute broadcast result shape."""
    if not shapes:
        return Shape.unknown()
    
    result = shapes[0]
    for shape in shapes[1:]:
        result = result.broadcast_with(shape)
        if result is None:
            return Shape.unknown()
    return result


def matmul_shape(a: Shape, b: Shape) -> Shape:
    """Compute matrix multiplication result shape."""
    if not a.is_known or not b.is_known:
        return Shape.unknown()
    
    if a.rank == 1 and b.rank == 1:
        return Shape.scalar()
    elif a.rank == 1:
        # (n,) @ (n, m) -> (m,)
        return Shape.vector(b[-1])
    elif b.rank == 1:
        # (m, n) @ (n,) -> (m,)
        return Shape.vector(a[-2])
    else:
        # (..., m, n) @ (..., n, p) -> (..., m, p)
        # For now, simplified
        return Shape.unknown()


def conv_output_shape(input_shape: Shape, kernel_size: int, 
                      stride: int = 1, padding: int = 0) -> Shape:
    """Compute convolution output shape."""
    if not input_shape.is_known:
        return Shape.unknown()
    
    # Simplified for 1D
    if input_shape.rank >= 1 and input_shape[-1].is_concrete:
        in_size = input_shape[-1].concrete
        out_size = (in_size + 2 * padding - kernel_size) // stride + 1
        # Would need to construct proper shape
        return Shape.unknown()
    
    return Shape.unknown()


# =============================================================================
# Device Propagation Helpers
# =============================================================================

def same_device_as_first(tensors: List[Any]) -> Device:
    """Return device of first tensor."""
    if tensors and hasattr(tensors[0], 'device'):
        return tensors[0].device
    return Device.unknown()


def check_all_same_device(tensors: List[Any]) -> bool:
    """Check if all tensors are on the same device."""
    if len(tensors) < 2:
        return True
    
    first_device = getattr(tensors[0], 'device', None)
    if first_device is None:
        return False
    
    for t in tensors[1:]:
        device = getattr(t, 'device', None)
        if device is None or not first_device.compatible_with(device):
            return False
    
    return True


# =============================================================================
# Quick Contract Creators
# =============================================================================

def interval(name: str, module: str, lo: float, hi: float, 
             desc: str = "") -> FunctionContract:
    """Create an interval-bounded contract."""
    return FunctionContract(
        name=name,
        module=module,
        description=desc,
        return_interval=Interval(lo, hi),
        preserves_device=True,
    )


def positive(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create a positive-return contract."""
    return FunctionContract(
        name=name,
        module=module,
        description=desc,
        return_interval=Interval.positive(),
        guarantees_positive=True,
        guarantees_non_negative=True,
        guarantees_non_zero=True,
        preserves_device=True,
    )


def non_negative(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create a non-negative-return contract."""
    return FunctionContract(
        name=name,
        module=module,
        description=desc,
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    )


def probability(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create a probability [0,1] contract."""
    return interval(name, module, 0.0, 1.0, desc)


def symmetric_unit(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create a [-1, 1] contract."""
    return interval(name, module, -1.0, 1.0, desc)


def angle(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create an angle [-π, π] contract."""
    return interval(name, module, -math.pi, math.pi, desc)


def unbounded(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create an unbounded contract (just for device tracking)."""
    return FunctionContract(
        name=name,
        module=module,
        description=desc,
        preserves_device=True,
    )


def shape_preserving(name: str, module: str, desc: str = "") -> FunctionContract:
    """Create a shape-preserving contract."""
    return FunctionContract(
        name=name,
        module=module,
        description=desc,
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    )
