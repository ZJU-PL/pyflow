"""
PyTorch Tensor Method Contracts

This module provides contracts for all tensor instance methods.
These are called as methods on tensor objects (e.g., tensor.sum()).

Includes:
- In-place operations (end with _)
- Properties (shape, dtype, device, etc.)
- Views and data manipulation
- Reduction methods
- Mathematical methods
"""

from typing import Optional, List, Dict, Any, Tuple
import math

from ..intervals import Interval
from ..contracts import (
    LibraryContract, MethodContract, PropertyContract, ContractRegistry,
    ContractBuilder, Precondition, Postcondition
)
from ..abstract_values import Shape, DType, Device, AbstractTensor

from .registry import bulk_register


def register_tensor_contracts(registry: ContractRegistry) -> None:
    """Register all tensor method contracts."""
    
    contracts = []
    
    # =========================================================================
    # PROPERTIES (read-only attributes)
    # =========================================================================
    
    contracts.append(PropertyContract(
        name="shape",
        module="torch.Tensor",
        description="Tensor shape",
        return_type="torch.Size",
    ))
    
    contracts.append(PropertyContract(
        name="size",
        module="torch.Tensor",
        description="Tensor size (method form)",
        return_type="torch.Size",
    ))
    
    contracts.append(PropertyContract(
        name="dim",
        module="torch.Tensor",
        description="Number of dimensions",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="ndim",
        module="torch.Tensor",
        description="Number of dimensions (alias)",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="ndimension",
        module="torch.Tensor",
        description="Number of dimensions (method)",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="numel",
        module="torch.Tensor",
        description="Total number of elements",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="element_size",
        module="torch.Tensor",
        description="Bytes per element",
        return_interval=Interval.positive(),
    ))
    
    contracts.append(PropertyContract(
        name="dtype",
        module="torch.Tensor",
        description="Data type",
        return_type="torch.dtype",
    ))
    
    contracts.append(PropertyContract(
        name="device",
        module="torch.Tensor",
        description="Device location",
        return_type="torch.device",
    ))
    
    contracts.append(PropertyContract(
        name="layout",
        module="torch.Tensor",
        description="Memory layout",
        return_type="torch.layout",
    ))
    
    contracts.append(PropertyContract(
        name="requires_grad",
        module="torch.Tensor",
        description="Whether requires gradient",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="grad",
        module="torch.Tensor",
        description="Gradient tensor",
        return_type="Optional[torch.Tensor]",
    ))
    
    contracts.append(PropertyContract(
        name="grad_fn",
        module="torch.Tensor",
        description="Gradient function",
        return_type="Optional[torch.autograd.Node]",
    ))
    
    contracts.append(PropertyContract(
        name="is_leaf",
        module="torch.Tensor",
        description="Whether leaf tensor",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="data",
        module="torch.Tensor",
        description="Underlying data tensor",
        return_type="torch.Tensor",
    ))
    
    contracts.append(PropertyContract(
        name="T",
        module="torch.Tensor",
        description="Transpose (2D only)",
        return_type="torch.Tensor",
        preserves_device=True,
    ))
    
    contracts.append(PropertyContract(
        name="H",
        module="torch.Tensor",
        description="Conjugate transpose",
        return_type="torch.Tensor",
        preserves_device=True,
    ))
    
    contracts.append(PropertyContract(
        name="mT",
        module="torch.Tensor",
        description="Matrix transpose",
        return_type="torch.Tensor",
        preserves_device=True,
    ))
    
    contracts.append(PropertyContract(
        name="mH",
        module="torch.Tensor",
        description="Matrix Hermitian transpose",
        return_type="torch.Tensor",
        preserves_device=True,
    ))
    
    contracts.append(PropertyContract(
        name="real",
        module="torch.Tensor",
        description="Real part",
        return_type="torch.Tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(PropertyContract(
        name="imag",
        module="torch.Tensor",
        description="Imaginary part",
        return_type="torch.Tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(PropertyContract(
        name="is_cuda",
        module="torch.Tensor",
        description="Whether on CUDA",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="is_cpu",
        module="torch.Tensor",
        description="Whether on CPU",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="is_sparse",
        module="torch.Tensor",
        description="Whether sparse",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="is_quantized",
        module="torch.Tensor",
        description="Whether quantized",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="is_meta",
        module="torch.Tensor",
        description="Whether meta tensor",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="is_contiguous",
        module="torch.Tensor",
        description="Whether contiguous",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="is_pinned",
        module="torch.Tensor",
        description="Whether pinned memory",
        return_type="bool",
    ))
    
    contracts.append(PropertyContract(
        name="nbytes",
        module="torch.Tensor",
        description="Total bytes",
        return_interval=Interval.non_negative(),
    ))
    
    contracts.append(PropertyContract(
        name="itemsize",
        module="torch.Tensor",
        description="Bytes per element",
        return_interval=Interval.positive(),
    ))
    
    contracts.append(PropertyContract(
        name="strides",
        module="torch.Tensor",
        description="Strides in elements",
        return_type="Tuple[int, ...]",
    ))
    
    # =========================================================================
    # MATHEMATICAL METHODS (element-wise)
    # =========================================================================
    
    contracts.append(MethodContract(
        name="abs",
        module="torch.Tensor",
        description="Absolute value",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="abs_",
        module="torch.Tensor",
        description="In-place absolute value",
        return_interval=Interval.non_negative(),
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="absolute",
        module="torch.Tensor",
        description="Absolute value (alias)",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="absolute_",
        module="torch.Tensor",
        description="In-place absolute (alias)",
        return_interval=Interval.non_negative(),
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="acos",
        module="torch.Tensor",
        description="Arc cosine",
        preconditions=[Precondition("-1 <= self <= 1", "Input in [-1, 1]")],
        return_interval=Interval(0, math.pi),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="acos_",
        module="torch.Tensor",
        description="In-place arc cosine",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arccos",
        module="torch.Tensor",
        description="Arc cosine (alias)",
        preconditions=[Precondition("-1 <= self <= 1", "Input in [-1, 1]")],
        return_interval=Interval(0, math.pi),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arccos_",
        module="torch.Tensor",
        description="In-place arc cosine (alias)",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="acosh",
        module="torch.Tensor",
        description="Inverse hyperbolic cosine",
        preconditions=[Precondition("self >= 1", "Input >= 1")],
        return_interval=Interval.non_negative(),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="acosh_",
        module="torch.Tensor",
        description="In-place acosh",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="add",
        module="torch.Tensor",
        description="Addition",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="add_",
        module="torch.Tensor",
        description="In-place addition",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="addcdiv",
        module="torch.Tensor",
        description="self + value * t1/t2",
        preconditions=[Precondition("t2 != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="addcdiv_",
        module="torch.Tensor",
        description="In-place addcdiv",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="addcmul",
        module="torch.Tensor",
        description="self + value * t1 * t2",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="addcmul_",
        module="torch.Tensor",
        description="In-place addcmul",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="addmm",
        module="torch.Tensor",
        description="beta*self + alpha*m1@m2",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="addmm_",
        module="torch.Tensor",
        description="In-place addmm",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="addmv",
        module="torch.Tensor",
        description="beta*self + alpha*m@v",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="addmv_",
        module="torch.Tensor",
        description="In-place addmv",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="addr",
        module="torch.Tensor",
        description="beta*self + alpha*outer(v1,v2)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="addr_",
        module="torch.Tensor",
        description="In-place addr",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="all",
        module="torch.Tensor",
        description="Test if all True",
        return_type="bool",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="allclose",
        module="torch.Tensor",
        description="All elements close",
        return_type="bool",
        requires_same_device=True,
    ))
    
    contracts.append(MethodContract(
        name="amax",
        module="torch.Tensor",
        description="Maximum along dim",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="amin",
        module="torch.Tensor",
        description="Minimum along dim",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="aminmax",
        module="torch.Tensor",
        description="Min and max together",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="angle",
        module="torch.Tensor",
        description="Phase angle",
        return_interval=Interval(-math.pi, math.pi),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="any",
        module="torch.Tensor",
        description="Test if any True",
        return_type="bool",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="apply_",
        module="torch.Tensor",
        description="Apply function in-place",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="argmax",
        module="torch.Tensor",
        description="Index of maximum",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="argmin",
        module="torch.Tensor",
        description="Index of minimum",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="argsort",
        module="torch.Tensor",
        description="Sorting indices",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="asin",
        module="torch.Tensor",
        description="Arc sine",
        preconditions=[Precondition("-1 <= self <= 1", "Input in [-1, 1]")],
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="asin_",
        module="torch.Tensor",
        description="In-place arc sine",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arcsin",
        module="torch.Tensor",
        description="Arc sine (alias)",
        preconditions=[Precondition("-1 <= self <= 1", "Input in [-1, 1]")],
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arcsin_",
        module="torch.Tensor",
        description="In-place arcsin (alias)",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="asinh",
        module="torch.Tensor",
        description="Inverse hyperbolic sine",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="asinh_",
        module="torch.Tensor",
        description="In-place asinh",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arcsinh",
        module="torch.Tensor",
        description="Inverse hyperbolic sine (alias)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arcsinh_",
        module="torch.Tensor",
        description="In-place arcsinh (alias)",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="atan",
        module="torch.Tensor",
        description="Arc tangent",
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="atan_",
        module="torch.Tensor",
        description="In-place atan",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arctan",
        module="torch.Tensor",
        description="Arc tangent (alias)",
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arctan_",
        module="torch.Tensor",
        description="In-place arctan (alias)",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="atan2",
        module="torch.Tensor",
        description="Two-argument arc tangent",
        return_interval=Interval(-math.pi, math.pi),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="atan2_",
        module="torch.Tensor",
        description="In-place atan2",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arctan2",
        module="torch.Tensor",
        description="Two-argument arctangent (alias)",
        return_interval=Interval(-math.pi, math.pi),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arctan2_",
        module="torch.Tensor",
        description="In-place arctan2 (alias)",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="atanh",
        module="torch.Tensor",
        description="Inverse hyperbolic tangent",
        preconditions=[Precondition("-1 < self < 1", "Input in (-1, 1)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="atanh_",
        module="torch.Tensor",
        description="In-place atanh",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arctanh",
        module="torch.Tensor",
        description="Inverse hyperbolic tangent (alias)",
        preconditions=[Precondition("-1 < self < 1", "Input in (-1, 1)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="arctanh_",
        module="torch.Tensor",
        description="In-place arctanh (alias)",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Batch operations ---
    
    contracts.append(MethodContract(
        name="baddbmm",
        module="torch.Tensor",
        description="Batched add matrix-matrix",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="baddbmm_",
        module="torch.Tensor",
        description="In-place baddbmm",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="bernoulli",
        module="torch.Tensor",
        description="Bernoulli samples",
        return_interval=Interval(0.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bernoulli_",
        module="torch.Tensor",
        description="In-place Bernoulli",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bfloat16",
        module="torch.Tensor",
        description="Convert to bfloat16",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bincount",
        module="torch.Tensor",
        description="Count integer occurrences",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_and",
        module="torch.Tensor",
        description="Bitwise AND",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_and_",
        module="torch.Tensor",
        description="In-place bitwise AND",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_not",
        module="torch.Tensor",
        description="Bitwise NOT",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_not_",
        module="torch.Tensor",
        description="In-place bitwise NOT",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_or",
        module="torch.Tensor",
        description="Bitwise OR",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_or_",
        module="torch.Tensor",
        description="In-place bitwise OR",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_xor",
        module="torch.Tensor",
        description="Bitwise XOR",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_xor_",
        module="torch.Tensor",
        description="In-place bitwise XOR",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_left_shift",
        module="torch.Tensor",
        description="Bitwise left shift",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_left_shift_",
        module="torch.Tensor",
        description="In-place left shift",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_right_shift",
        module="torch.Tensor",
        description="Bitwise right shift",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bitwise_right_shift_",
        module="torch.Tensor",
        description="In-place right shift",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="bmm",
        module="torch.Tensor",
        description="Batched matrix multiply",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="bool",
        module="torch.Tensor",
        description="Convert to bool",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- C ---
    
    contracts.append(MethodContract(
        name="cauchy_",
        module="torch.Tensor",
        description="Fill with Cauchy samples",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ceil",
        module="torch.Tensor",
        description="Ceiling",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ceil_",
        module="torch.Tensor",
        description="In-place ceiling",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="char",
        module="torch.Tensor",
        description="Convert to int8",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cholesky",
        module="torch.Tensor",
        description="Cholesky decomposition",
        preconditions=[Precondition("self is positive definite", "Matrix must be positive definite")],
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="cholesky_inverse",
        module="torch.Tensor",
        description="Inverse via Cholesky",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="cholesky_solve",
        module="torch.Tensor",
        description="Solve via Cholesky",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="chunk",
        module="torch.Tensor",
        description="Split into chunks",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="clamp",
        module="torch.Tensor",
        description="Clamp to range",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clamp_",
        module="torch.Tensor",
        description="In-place clamp",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clip",
        module="torch.Tensor",
        description="Clip (alias for clamp)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clip_",
        module="torch.Tensor",
        description="In-place clip",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clamp_min",
        module="torch.Tensor",
        description="Clamp to minimum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clamp_min_",
        module="torch.Tensor",
        description="In-place clamp min",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clamp_max",
        module="torch.Tensor",
        description="Clamp to maximum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clamp_max_",
        module="torch.Tensor",
        description="In-place clamp max",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="clone",
        module="torch.Tensor",
        description="Clone tensor",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="conj",
        module="torch.Tensor",
        description="Complex conjugate",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="conj_physical",
        module="torch.Tensor",
        description="Physical conjugate",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="conj_physical_",
        module="torch.Tensor",
        description="In-place physical conjugate",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="contiguous",
        module="torch.Tensor",
        description="Make contiguous",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="copy_",
        module="torch.Tensor",
        description="Copy from other tensor",
        requires_same_device=False,  # Can copy across devices
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="copysign",
        module="torch.Tensor",
        description="Copy sign from other",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="copysign_",
        module="torch.Tensor",
        description="In-place copysign",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cos",
        module="torch.Tensor",
        description="Cosine",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cos_",
        module="torch.Tensor",
        description="In-place cosine",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cosh",
        module="torch.Tensor",
        description="Hyperbolic cosine",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cosh_",
        module="torch.Tensor",
        description="In-place cosh",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="count_nonzero",
        module="torch.Tensor",
        description="Count non-zeros",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="cpu",
        module="torch.Tensor",
        description="Move to CPU",
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="cross",
        module="torch.Tensor",
        description="Cross product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="cuda",
        module="torch.Tensor",
        description="Move to CUDA",
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="cummax",
        module="torch.Tensor",
        description="Cumulative maximum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cummin",
        module="torch.Tensor",
        description="Cumulative minimum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cumprod",
        module="torch.Tensor",
        description="Cumulative product",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cumprod_",
        module="torch.Tensor",
        description="In-place cumprod",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cumsum",
        module="torch.Tensor",
        description="Cumulative sum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="cumsum_",
        module="torch.Tensor",
        description="In-place cumsum",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- D ---
    
    contracts.append(MethodContract(
        name="deg2rad",
        module="torch.Tensor",
        description="Degrees to radians",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="deg2rad_",
        module="torch.Tensor",
        description="In-place deg2rad",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="dequantize",
        module="torch.Tensor",
        description="Dequantize tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="det",
        module="torch.Tensor",
        description="Determinant",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="detach",
        module="torch.Tensor",
        description="Detach from graph",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="detach_",
        module="torch.Tensor",
        description="In-place detach",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="diag",
        module="torch.Tensor",
        description="Diagonal matrix or vector",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="diag_embed",
        module="torch.Tensor",
        description="Embed vector as diagonal",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="diagflat",
        module="torch.Tensor",
        description="Create diagonal matrix",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="diagonal",
        module="torch.Tensor",
        description="Extract diagonal",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="diagonal_scatter",
        module="torch.Tensor",
        description="Scatter to diagonal",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="diff",
        module="torch.Tensor",
        description="Differences",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="digamma",
        module="torch.Tensor",
        description="Digamma function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="digamma_",
        module="torch.Tensor",
        description="In-place digamma",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="dist",
        module="torch.Tensor",
        description="p-norm distance",
        requires_same_device=True,
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="div",
        module="torch.Tensor",
        description="Division",
        preconditions=[Precondition("other != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="div_",
        module="torch.Tensor",
        description="In-place division",
        preconditions=[Precondition("other != 0", "Divisor non-zero")],
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="divide",
        module="torch.Tensor",
        description="Division (alias)",
        preconditions=[Precondition("other != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="divide_",
        module="torch.Tensor",
        description="In-place divide (alias)",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="dot",
        module="torch.Tensor",
        description="Dot product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="double",
        module="torch.Tensor",
        description="Convert to float64",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="dsplit",
        module="torch.Tensor",
        description="Split depth-wise",
        preserves_device=True,
    ))
    
    # --- E ---
    
    contracts.append(MethodContract(
        name="eq",
        module="torch.Tensor",
        description="Element-wise equality",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="eq_",
        module="torch.Tensor",
        description="In-place eq",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="equal",
        module="torch.Tensor",
        description="Tensor equality",
        return_type="bool",
        requires_same_device=True,
    ))
    
    contracts.append(MethodContract(
        name="erf",
        module="torch.Tensor",
        description="Error function",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="erf_",
        module="torch.Tensor",
        description="In-place erf",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="erfc",
        module="torch.Tensor",
        description="Complementary error function",
        return_interval=Interval(0.0, 2.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="erfc_",
        module="torch.Tensor",
        description="In-place erfc",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="erfinv",
        module="torch.Tensor",
        description="Inverse error function",
        preconditions=[Precondition("-1 < self < 1", "Input in (-1, 1)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="erfinv_",
        module="torch.Tensor",
        description="In-place erfinv",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="exp",
        module="torch.Tensor",
        description="Exponential",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        guarantees_non_zero=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="exp_",
        module="torch.Tensor",
        description="In-place exp",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="exp2",
        module="torch.Tensor",
        description="Base-2 exponential",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="exp2_",
        module="torch.Tensor",
        description="In-place exp2",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="expand",
        module="torch.Tensor",
        description="Expand to size",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="expand_as",
        module="torch.Tensor",
        description="Expand to match other",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="expm1",
        module="torch.Tensor",
        description="exp(x) - 1",
        return_interval=Interval(-1.0, float('inf')),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="expm1_",
        module="torch.Tensor",
        description="In-place expm1",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="exponential_",
        module="torch.Tensor",
        description="Fill with exponential samples",
        return_interval=Interval.non_negative(),
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- F ---
    
    contracts.append(MethodContract(
        name="fill_",
        module="torch.Tensor",
        description="Fill with value",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="fill_diagonal_",
        module="torch.Tensor",
        description="Fill diagonal",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="fix",
        module="torch.Tensor",
        description="Truncate to integer",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="fix_",
        module="torch.Tensor",
        description="In-place fix",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="flatten",
        module="torch.Tensor",
        description="Flatten to 1D or range",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="flip",
        module="torch.Tensor",
        description="Flip along dims",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="fliplr",
        module="torch.Tensor",
        description="Flip left-right",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="flipud",
        module="torch.Tensor",
        description="Flip up-down",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="float",
        module="torch.Tensor",
        description="Convert to float32",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="floor",
        module="torch.Tensor",
        description="Floor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="floor_",
        module="torch.Tensor",
        description="In-place floor",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="floor_divide",
        module="torch.Tensor",
        description="Floor division",
        preconditions=[Precondition("other != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="floor_divide_",
        module="torch.Tensor",
        description="In-place floor_divide",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="fmod",
        module="torch.Tensor",
        description="C-style remainder",
        preconditions=[Precondition("other != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="fmod_",
        module="torch.Tensor",
        description="In-place fmod",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="frac",
        module="torch.Tensor",
        description="Fractional part",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="frac_",
        module="torch.Tensor",
        description="In-place frac",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="frexp",
        module="torch.Tensor",
        description="Mantissa and exponent",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- G ---
    
    contracts.append(MethodContract(
        name="gather",
        module="torch.Tensor",
        description="Gather along dim",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="gcd",
        module="torch.Tensor",
        description="Greatest common divisor",
        requires_same_device=True,
        return_interval=Interval.non_negative(),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="gcd_",
        module="torch.Tensor",
        description="In-place gcd",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ge",
        module="torch.Tensor",
        description="Greater or equal",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ge_",
        module="torch.Tensor",
        description="In-place ge",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="greater_equal",
        module="torch.Tensor",
        description="Greater or equal (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="greater_equal_",
        module="torch.Tensor",
        description="In-place greater_equal",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="geometric_",
        module="torch.Tensor",
        description="Fill with geometric samples",
        return_interval=Interval(1.0, float('inf')),
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="geqrf",
        module="torch.Tensor",
        description="QR decomposition",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="ger",
        module="torch.Tensor",
        description="Outer product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="gt",
        module="torch.Tensor",
        description="Greater than",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="gt_",
        module="torch.Tensor",
        description="In-place gt",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="greater",
        module="torch.Tensor",
        description="Greater than (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="greater_",
        module="torch.Tensor",
        description="In-place greater",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- H ---
    
    contracts.append(MethodContract(
        name="half",
        module="torch.Tensor",
        description="Convert to float16",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="hardshrink",
        module="torch.Tensor",
        description="Hard shrink",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="heaviside",
        module="torch.Tensor",
        description="Heaviside step",
        return_interval=Interval(0.0, 1.0),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="histc",
        module="torch.Tensor",
        description="Histogram",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="histogram",
        module="torch.Tensor",
        description="Histogram",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="hsplit",
        module="torch.Tensor",
        description="Horizontal split",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="hypot",
        module="torch.Tensor",
        description="Hypotenuse",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="hypot_",
        module="torch.Tensor",
        description="In-place hypot",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- I ---
    
    contracts.append(MethodContract(
        name="i0",
        module="torch.Tensor",
        description="Modified Bessel I0",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="i0_",
        module="torch.Tensor",
        description="In-place i0",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="igamma",
        module="torch.Tensor",
        description="Lower incomplete gamma",
        requires_same_device=True,
        return_interval=Interval(0.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="igamma_",
        module="torch.Tensor",
        description="In-place igamma",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="igammac",
        module="torch.Tensor",
        description="Upper incomplete gamma",
        requires_same_device=True,
        return_interval=Interval(0.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="igammac_",
        module="torch.Tensor",
        description="In-place igammac",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_add",
        module="torch.Tensor",
        description="Index add",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_add_",
        module="torch.Tensor",
        description="In-place index add",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_copy",
        module="torch.Tensor",
        description="Index copy",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_copy_",
        module="torch.Tensor",
        description="In-place index copy",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_fill",
        module="torch.Tensor",
        description="Index fill",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_fill_",
        module="torch.Tensor",
        description="In-place index fill",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_put",
        module="torch.Tensor",
        description="Index put",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_put_",
        module="torch.Tensor",
        description="In-place index put",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_reduce",
        module="torch.Tensor",
        description="Index reduce",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_reduce_",
        module="torch.Tensor",
        description="In-place index reduce",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="index_select",
        module="torch.Tensor",
        description="Index select",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="indices",
        module="torch.Tensor",
        description="Sparse indices",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="inner",
        module="torch.Tensor",
        description="Inner product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="int",
        module="torch.Tensor",
        description="Convert to int32",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="int_repr",
        module="torch.Tensor",
        description="Integer representation",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="inverse",
        module="torch.Tensor",
        description="Matrix inverse",
        preconditions=[Precondition("det(self) != 0", "Matrix must be invertible")],
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="isclose",
        module="torch.Tensor",
        description="Elements close",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="isfinite",
        module="torch.Tensor",
        description="Test finite",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="isinf",
        module="torch.Tensor",
        description="Test infinite",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="isnan",
        module="torch.Tensor",
        description="Test NaN",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="isneginf",
        module="torch.Tensor",
        description="Test negative infinity",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="isposinf",
        module="torch.Tensor",
        description="Test positive infinity",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="isreal",
        module="torch.Tensor",
        description="Test real",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="istft",
        module="torch.Tensor",
        description="Inverse STFT",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="item",
        module="torch.Tensor",
        description="Get scalar value",
        return_type="float",
    ))
    
    # --- K/L ---
    
    contracts.append(MethodContract(
        name="kron",
        module="torch.Tensor",
        description="Kronecker product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="kthvalue",
        module="torch.Tensor",
        description="k-th smallest",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="lcm",
        module="torch.Tensor",
        description="Least common multiple",
        requires_same_device=True,
        return_interval=Interval.non_negative(),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lcm_",
        module="torch.Tensor",
        description="In-place lcm",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ldexp",
        module="torch.Tensor",
        description="x * 2^exp",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ldexp_",
        module="torch.Tensor",
        description="In-place ldexp",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="le",
        module="torch.Tensor",
        description="Less or equal",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="le_",
        module="torch.Tensor",
        description="In-place le",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="less_equal",
        module="torch.Tensor",
        description="Less or equal (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="less_equal_",
        module="torch.Tensor",
        description="In-place less_equal",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lerp",
        module="torch.Tensor",
        description="Linear interpolation",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lerp_",
        module="torch.Tensor",
        description="In-place lerp",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lgamma",
        module="torch.Tensor",
        description="Log gamma",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lgamma_",
        module="torch.Tensor",
        description="In-place lgamma",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log",
        module="torch.Tensor",
        description="Natural logarithm",
        preconditions=[Precondition("self > 0", "Input must be positive")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log_",
        module="torch.Tensor",
        description="In-place log",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log10",
        module="torch.Tensor",
        description="Base-10 logarithm",
        preconditions=[Precondition("self > 0", "Input must be positive")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log10_",
        module="torch.Tensor",
        description="In-place log10",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log1p",
        module="torch.Tensor",
        description="log(1 + x)",
        preconditions=[Precondition("self > -1", "Input must be > -1")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log1p_",
        module="torch.Tensor",
        description="In-place log1p",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log2",
        module="torch.Tensor",
        description="Base-2 logarithm",
        preconditions=[Precondition("self > 0", "Input must be positive")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="log2_",
        module="torch.Tensor",
        description="In-place log2",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logaddexp",
        module="torch.Tensor",
        description="log(exp(x) + exp(y))",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logaddexp2",
        module="torch.Tensor",
        description="log2(2^x + 2^y)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logcumsumexp",
        module="torch.Tensor",
        description="Cumulative log-sum-exp",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logdet",
        module="torch.Tensor",
        description="Log determinant",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_and",
        module="torch.Tensor",
        description="Logical AND",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_and_",
        module="torch.Tensor",
        description="In-place logical AND",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_not",
        module="torch.Tensor",
        description="Logical NOT",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_not_",
        module="torch.Tensor",
        description="In-place logical NOT",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_or",
        module="torch.Tensor",
        description="Logical OR",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_or_",
        module="torch.Tensor",
        description="In-place logical OR",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_xor",
        module="torch.Tensor",
        description="Logical XOR",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logical_xor_",
        module="torch.Tensor",
        description="In-place logical XOR",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="logsumexp",
        module="torch.Tensor",
        description="Log sum exp",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="long",
        module="torch.Tensor",
        description="Convert to int64",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lt",
        module="torch.Tensor",
        description="Less than",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lt_",
        module="torch.Tensor",
        description="In-place lt",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="less",
        module="torch.Tensor",
        description="Less than (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="less_",
        module="torch.Tensor",
        description="In-place less",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="lu",
        module="torch.Tensor",
        description="LU decomposition",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="lu_solve",
        module="torch.Tensor",
        description="Solve via LU",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    # --- M ---
    
    contracts.append(MethodContract(
        name="map_",
        module="torch.Tensor",
        description="Apply function in-place",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="masked_fill",
        module="torch.Tensor",
        description="Fill with mask",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="masked_fill_",
        module="torch.Tensor",
        description="In-place masked fill",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="masked_scatter",
        module="torch.Tensor",
        description="Scatter with mask",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="masked_scatter_",
        module="torch.Tensor",
        description="In-place masked scatter",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="masked_select",
        module="torch.Tensor",
        description="Select with mask",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="matmul",
        module="torch.Tensor",
        description="Matrix product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="matrix_exp",
        module="torch.Tensor",
        description="Matrix exponential",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="matrix_power",
        module="torch.Tensor",
        description="Matrix power",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="max",
        module="torch.Tensor",
        description="Maximum",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="maximum",
        module="torch.Tensor",
        description="Element-wise max",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="mean",
        module="torch.Tensor",
        description="Mean",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="median",
        module="torch.Tensor",
        description="Median",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="min",
        module="torch.Tensor",
        description="Minimum",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="minimum",
        module="torch.Tensor",
        description="Element-wise min",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="mm",
        module="torch.Tensor",
        description="Matrix multiply",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="mode",
        module="torch.Tensor",
        description="Mode",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="moveaxis",
        module="torch.Tensor",
        description="Move axis",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="movedim",
        module="torch.Tensor",
        description="Move dimension",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="msort",
        module="torch.Tensor",
        description="Sort along dim 0",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="mul",
        module="torch.Tensor",
        description="Multiply",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="mul_",
        module="torch.Tensor",
        description="In-place multiply",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="multiply",
        module="torch.Tensor",
        description="Multiply (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="multiply_",
        module="torch.Tensor",
        description="In-place multiply (alias)",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="multinomial",
        module="torch.Tensor",
        description="Multinomial samples",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="mv",
        module="torch.Tensor",
        description="Matrix-vector product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="mvlgamma",
        module="torch.Tensor",
        description="Multivariate log-gamma",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="mvlgamma_",
        module="torch.Tensor",
        description="In-place mvlgamma",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- N ---
    
    contracts.append(MethodContract(
        name="nan_to_num",
        module="torch.Tensor",
        description="Replace NaN/Inf",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="nan_to_num_",
        module="torch.Tensor",
        description="In-place nan_to_num",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="nanmean",
        module="torch.Tensor",
        description="Mean ignoring NaN",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="nanmedian",
        module="torch.Tensor",
        description="Median ignoring NaN",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="nansum",
        module="torch.Tensor",
        description="Sum ignoring NaN",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="narrow",
        module="torch.Tensor",
        description="Narrow dimension",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="narrow_copy",
        module="torch.Tensor",
        description="Narrow with copy",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="ne",
        module="torch.Tensor",
        description="Not equal",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ne_",
        module="torch.Tensor",
        description="In-place ne",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="not_equal",
        module="torch.Tensor",
        description="Not equal (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="not_equal_",
        module="torch.Tensor",
        description="In-place not_equal",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="neg",
        module="torch.Tensor",
        description="Negation",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="neg_",
        module="torch.Tensor",
        description="In-place negation",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="negative",
        module="torch.Tensor",
        description="Negation (alias)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="negative_",
        module="torch.Tensor",
        description="In-place negative",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="new_empty",
        module="torch.Tensor",
        description="New empty tensor",
        preserves_device=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="new_full",
        module="torch.Tensor",
        description="New full tensor",
        preserves_device=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="new_ones",
        module="torch.Tensor",
        description="New ones tensor",
        return_interval=Interval(1.0, 1.0),
        preserves_device=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="new_zeros",
        module="torch.Tensor",
        description="New zeros tensor",
        return_interval=Interval(0.0, 0.0),
        preserves_device=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="nextafter",
        module="torch.Tensor",
        description="Next floating point",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="nextafter_",
        module="torch.Tensor",
        description="In-place nextafter",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="nonzero",
        module="torch.Tensor",
        description="Non-zero indices",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="norm",
        module="torch.Tensor",
        description="Norm",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="normal_",
        module="torch.Tensor",
        description="Fill with normal",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="numpy",
        module="torch.Tensor",
        description="Convert to NumPy",
    ))
    
    # --- O/P ---
    
    contracts.append(MethodContract(
        name="orgqr",
        module="torch.Tensor",
        description="Orthogonal matrix from QR",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="ormqr",
        module="torch.Tensor",
        description="Multiply by Q from QR",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="outer",
        module="torch.Tensor",
        description="Outer product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="permute",
        module="torch.Tensor",
        description="Permute dimensions",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="pin_memory",
        module="torch.Tensor",
        description="Pin to memory",
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="pinverse",
        module="torch.Tensor",
        description="Pseudo-inverse",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="polygamma",
        module="torch.Tensor",
        description="Polygamma function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="polygamma_",
        module="torch.Tensor",
        description="In-place polygamma",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="positive",
        module="torch.Tensor",
        description="Unary positive",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="pow",
        module="torch.Tensor",
        description="Power",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="pow_",
        module="torch.Tensor",
        description="In-place power",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="prelu",
        module="torch.Tensor",
        description="PReLU activation",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="prod",
        module="torch.Tensor",
        description="Product",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="put",
        module="torch.Tensor",
        description="Put by indices",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="put_",
        module="torch.Tensor",
        description="In-place put",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Q/R ---
    
    contracts.append(MethodContract(
        name="qr",
        module="torch.Tensor",
        description="QR decomposition",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="quantile",
        module="torch.Tensor",
        description="Quantiles",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="rad2deg",
        module="torch.Tensor",
        description="Radians to degrees",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="rad2deg_",
        module="torch.Tensor",
        description="In-place rad2deg",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="random_",
        module="torch.Tensor",
        description="Fill with random",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="ravel",
        module="torch.Tensor",
        description="Flatten to 1D",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="reciprocal",
        module="torch.Tensor",
        description="1/x",
        preconditions=[Precondition("self != 0", "Input must be non-zero")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="reciprocal_",
        module="torch.Tensor",
        description="In-place reciprocal",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="relu",
        module="torch.Tensor",
        description="ReLU",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="relu_",
        module="torch.Tensor",
        description="In-place ReLU",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="remainder",
        module="torch.Tensor",
        description="Python-style remainder",
        preconditions=[Precondition("divisor != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="remainder_",
        module="torch.Tensor",
        description="In-place remainder",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="repeat",
        module="torch.Tensor",
        description="Repeat tensor",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="repeat_interleave",
        module="torch.Tensor",
        description="Repeat elements",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="requires_grad_",
        module="torch.Tensor",
        description="Set requires_grad",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="reshape",
        module="torch.Tensor",
        description="Reshape tensor",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="reshape_as",
        module="torch.Tensor",
        description="Reshape to match",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="resize_",
        module="torch.Tensor",
        description="Resize tensor",
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="resize_as_",
        module="torch.Tensor",
        description="Resize to match",
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="roll",
        module="torch.Tensor",
        description="Roll tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="rot90",
        module="torch.Tensor",
        description="Rotate 90 degrees",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="round",
        module="torch.Tensor",
        description="Round",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="round_",
        module="torch.Tensor",
        description="In-place round",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="rsqrt",
        module="torch.Tensor",
        description="1/sqrt(x)",
        preconditions=[Precondition("self > 0", "Input must be positive")],
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="rsqrt_",
        module="torch.Tensor",
        description="In-place rsqrt",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- S ---
    
    contracts.append(MethodContract(
        name="scatter",
        module="torch.Tensor",
        description="Scatter values",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="scatter_",
        module="torch.Tensor",
        description="In-place scatter",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="scatter_add",
        module="torch.Tensor",
        description="Scatter add",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="scatter_add_",
        module="torch.Tensor",
        description="In-place scatter add",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="scatter_reduce",
        module="torch.Tensor",
        description="Scatter reduce",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="scatter_reduce_",
        module="torch.Tensor",
        description="In-place scatter reduce",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="select",
        module="torch.Tensor",
        description="Select index",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="select_scatter",
        module="torch.Tensor",
        description="Select scatter",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="sgn",
        module="torch.Tensor",
        description="Sign for complex",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sgn_",
        module="torch.Tensor",
        description="In-place sgn",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="short",
        module="torch.Tensor",
        description="Convert to int16",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sigmoid",
        module="torch.Tensor",
        description="Sigmoid",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sigmoid_",
        module="torch.Tensor",
        description="In-place sigmoid",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sign",
        module="torch.Tensor",
        description="Sign (-1, 0, 1)",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sign_",
        module="torch.Tensor",
        description="In-place sign",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="signbit",
        module="torch.Tensor",
        description="Sign bit",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sin",
        module="torch.Tensor",
        description="Sine",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sin_",
        module="torch.Tensor",
        description="In-place sin",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sinc",
        module="torch.Tensor",
        description="Sinc function",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sinc_",
        module="torch.Tensor",
        description="In-place sinc",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sinh",
        module="torch.Tensor",
        description="Hyperbolic sine",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sinh_",
        module="torch.Tensor",
        description="In-place sinh",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="slice_scatter",
        module="torch.Tensor",
        description="Slice scatter",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="softmax",
        module="torch.Tensor",
        description="Softmax",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="solve",
        module="torch.Tensor",
        description="Solve linear system",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="sort",
        module="torch.Tensor",
        description="Sort",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="split",
        module="torch.Tensor",
        description="Split tensor",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="sqrt",
        module="torch.Tensor",
        description="Square root",
        preconditions=[Precondition("self >= 0", "Input must be non-negative")],
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sqrt_",
        module="torch.Tensor",
        description="In-place sqrt",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="square",
        module="torch.Tensor",
        description="Square",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="square_",
        module="torch.Tensor",
        description="In-place square",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="squeeze",
        module="torch.Tensor",
        description="Remove size-1 dims",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="squeeze_",
        module="torch.Tensor",
        description="In-place squeeze",
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="std",
        module="torch.Tensor",
        description="Standard deviation",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="stft",
        module="torch.Tensor",
        description="Short-time Fourier",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="sub",
        module="torch.Tensor",
        description="Subtraction",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sub_",
        module="torch.Tensor",
        description="In-place subtraction",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="subtract",
        module="torch.Tensor",
        description="Subtraction (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="subtract_",
        module="torch.Tensor",
        description="In-place subtract (alias)",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="sum",
        module="torch.Tensor",
        description="Sum",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="sum_to_size",
        module="torch.Tensor",
        description="Sum to size",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="svd",
        module="torch.Tensor",
        description="SVD decomposition",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="swapaxes",
        module="torch.Tensor",
        description="Swap axes",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="swapdims",
        module="torch.Tensor",
        description="Swap dimensions",
        preserves_device=True,
    ))
    
    # --- T ---
    
    contracts.append(MethodContract(
        name="t",
        module="torch.Tensor",
        description="2D transpose",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="t_",
        module="torch.Tensor",
        description="In-place transpose",
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="take",
        module="torch.Tensor",
        description="Take by indices",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="take_along_dim",
        module="torch.Tensor",
        description="Take along dim",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="tan",
        module="torch.Tensor",
        description="Tangent",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="tan_",
        module="torch.Tensor",
        description="In-place tangent",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="tanh",
        module="torch.Tensor",
        description="Hyperbolic tangent",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="tanh_",
        module="torch.Tensor",
        description="In-place tanh",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="tensor_split",
        module="torch.Tensor",
        description="Split tensor",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="tile",
        module="torch.Tensor",
        description="Tile tensor",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="to",
        module="torch.Tensor",
        description="Convert dtype/device",
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="tolist",
        module="torch.Tensor",
        description="Convert to list",
    ))
    
    contracts.append(MethodContract(
        name="topk",
        module="torch.Tensor",
        description="Top-k values",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="trace",
        module="torch.Tensor",
        description="Matrix trace",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="transpose",
        module="torch.Tensor",
        description="Transpose dimensions",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="transpose_",
        module="torch.Tensor",
        description="In-place transpose",
        modifies_input=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="triangular_solve",
        module="torch.Tensor",
        description="Triangular solve",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="tril",
        module="torch.Tensor",
        description="Lower triangular",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="tril_",
        module="torch.Tensor",
        description="In-place tril",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="triu",
        module="torch.Tensor",
        description="Upper triangular",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="triu_",
        module="torch.Tensor",
        description="In-place triu",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="true_divide",
        module="torch.Tensor",
        description="True division",
        preconditions=[Precondition("divisor != 0", "Divisor non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="true_divide_",
        module="torch.Tensor",
        description="In-place true_divide",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="trunc",
        module="torch.Tensor",
        description="Truncate",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="trunc_",
        module="torch.Tensor",
        description="In-place trunc",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="type",
        module="torch.Tensor",
        description="Cast type",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="type_as",
        module="torch.Tensor",
        description="Type as other",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- U ---
    
    contracts.append(MethodContract(
        name="unbind",
        module="torch.Tensor",
        description="Remove dimension",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="unflatten",
        module="torch.Tensor",
        description="Unflatten dimension",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="unfold",
        module="torch.Tensor",
        description="Unfold dimension",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="uniform_",
        module="torch.Tensor",
        description="Fill with uniform",
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="unique",
        module="torch.Tensor",
        description="Unique values",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="unique_consecutive",
        module="torch.Tensor",
        description="Unique consecutive",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="unsqueeze",
        module="torch.Tensor",
        description="Add dimension",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="unsqueeze_",
        module="torch.Tensor",
        description="In-place unsqueeze",
        modifies_input=True,
        preserves_device=True,
    ))
    
    # --- V ---
    
    contracts.append(MethodContract(
        name="values",
        module="torch.Tensor",
        description="Sparse values",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="var",
        module="torch.Tensor",
        description="Variance",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="vdot",
        module="torch.Tensor",
        description="Vector dot",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="view",
        module="torch.Tensor",
        description="View with shape",
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="view_as",
        module="torch.Tensor",
        description="View as other",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="vsplit",
        module="torch.Tensor",
        description="Vertical split",
        preserves_device=True,
    ))
    
    # --- W/X/Z ---
    
    contracts.append(MethodContract(
        name="where",
        module="torch.Tensor",
        description="Conditional select",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(MethodContract(
        name="xlogy",
        module="torch.Tensor",
        description="x * log(y)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="xlogy_",
        module="torch.Tensor",
        description="In-place xlogy",
        requires_same_device=True,
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(MethodContract(
        name="xpu",
        module="torch.Tensor",
        description="Move to XPU",
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(MethodContract(
        name="zero_",
        module="torch.Tensor",
        description="Fill with zeros",
        return_interval=Interval(0.0, 0.0),
        modifies_input=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
