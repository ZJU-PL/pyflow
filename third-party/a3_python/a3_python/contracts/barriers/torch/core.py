"""
PyTorch Core Function Contracts (torch.*)

This module provides contracts for all core PyTorch functions.
These are the fundamental tensor operations and mathematical functions.

Includes:
- Mathematical element-wise operations (exp, log, sin, cos, etc.)
- Reduction operations (sum, mean, max, min, etc.)
- Creation operations (zeros, ones, tensor, etc.)
- Manipulation operations (reshape, transpose, cat, etc.)
- Comparison operations (eq, ne, lt, gt, etc.)
- Indexing operations (index_select, gather, scatter, etc.)
"""

from typing import Optional, List, Dict, Any, Tuple
import math

from ..intervals import Interval
from ..contracts import (
    LibraryContract, FunctionContract, ContractRegistry,
    ContractBuilder, Precondition, Postcondition
)
from ..abstract_values import (
    Shape, DType, Device, AbstractTensor, AbstractValue
)
from ..deferred import DeferredBarrier, DeviceBarrier, TransformationTrace

from .registry import (
    interval, positive, non_negative, probability, symmetric_unit,
    angle, unbounded, shape_preserving, bulk_register
)


def register_core_contracts(registry: ContractRegistry) -> None:
    """Register all torch.* core contracts."""
    
    contracts = []
    
    # =========================================================================
    # MATHEMATICAL ELEMENT-WISE OPERATIONS
    # =========================================================================
    
    # --- Exponential and Logarithmic ---
    
    contracts.append(FunctionContract(
        name="exp",
        module="torch",
        description="Element-wise exponential",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        guarantees_non_zero=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="exp2",
        module="torch",
        description="Element-wise base-2 exponential",
        return_interval=Interval.positive(),
        guarantees_positive=True,
        guarantees_non_zero=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="expm1",
        module="torch",
        description="exp(x) - 1, more accurate near zero",
        return_interval=Interval(-1.0, float('inf')),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log",
        module="torch",
        description="Natural logarithm (requires positive input)",
        preconditions=[Precondition("x > 0", "Input must be positive")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log10",
        module="torch",
        description="Base-10 logarithm",
        preconditions=[Precondition("x > 0", "Input must be positive")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log2",
        module="torch",
        description="Base-2 logarithm",
        preconditions=[Precondition("x > 0", "Input must be positive")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="log1p",
        module="torch",
        description="log(1 + x), more accurate near zero",
        preconditions=[Precondition("x > -1", "Input must be > -1")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="logaddexp",
        module="torch",
        description="log(exp(x) + exp(y)), numerically stable",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,  # after broadcast
    ))
    
    contracts.append(FunctionContract(
        name="logaddexp2",
        module="torch",
        description="log2(2^x + 2^y), numerically stable",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Power and Root ---
    
    contracts.append(FunctionContract(
        name="pow",
        module="torch",
        description="Element-wise power",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="sqrt",
        module="torch",
        description="Square root (requires non-negative)",
        preconditions=[Precondition("x >= 0", "Input must be non-negative")],
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="rsqrt",
        module="torch",
        description="Reciprocal square root 1/sqrt(x)",
        preconditions=[Precondition("x > 0", "Input must be positive")],
        return_interval=Interval.positive(),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="square",
        module="torch",
        description="Element-wise square",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="cbrt",
        module="torch",
        description="Cube root",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Trigonometric ---
    
    contracts.append(FunctionContract(
        name="sin",
        module="torch",
        description="Sine",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="cos",
        module="torch",
        description="Cosine",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="tan",
        module="torch",
        description="Tangent",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="asin",
        module="torch",
        description="Arcsine",
        preconditions=[Precondition("-1 <= x <= 1", "Input in [-1, 1]")],
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arcsin",
        module="torch",
        description="Arcsine (alias)",
        preconditions=[Precondition("-1 <= x <= 1", "Input in [-1, 1]")],
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="acos",
        module="torch",
        description="Arccosine",
        preconditions=[Precondition("-1 <= x <= 1", "Input in [-1, 1]")],
        return_interval=Interval(0, math.pi),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arccos",
        module="torch",
        description="Arccosine (alias)",
        preconditions=[Precondition("-1 <= x <= 1", "Input in [-1, 1]")],
        return_interval=Interval(0, math.pi),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="atan",
        module="torch",
        description="Arctangent",
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arctan",
        module="torch",
        description="Arctangent (alias)",
        return_interval=Interval(-math.pi/2, math.pi/2),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="atan2",
        module="torch",
        description="Two-argument arctangent",
        return_interval=Interval(-math.pi, math.pi),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arctan2",
        module="torch",
        description="Two-argument arctangent (alias)",
        return_interval=Interval(-math.pi, math.pi),
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Hyperbolic ---
    
    contracts.append(FunctionContract(
        name="sinh",
        module="torch",
        description="Hyperbolic sine",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="cosh",
        module="torch",
        description="Hyperbolic cosine",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="tanh",
        module="torch",
        description="Hyperbolic tangent",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="asinh",
        module="torch",
        description="Inverse hyperbolic sine",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arcsinh",
        module="torch",
        description="Inverse hyperbolic sine (alias)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="acosh",
        module="torch",
        description="Inverse hyperbolic cosine",
        preconditions=[Precondition("x >= 1", "Input >= 1")],
        return_interval=Interval.non_negative(),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arccosh",
        module="torch",
        description="Inverse hyperbolic cosine (alias)",
        preconditions=[Precondition("x >= 1", "Input >= 1")],
        return_interval=Interval.non_negative(),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="atanh",
        module="torch",
        description="Inverse hyperbolic tangent",
        preconditions=[Precondition("-1 < x < 1", "Input in (-1, 1)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="arctanh",
        module="torch",
        description="Inverse hyperbolic tangent (alias)",
        preconditions=[Precondition("-1 < x < 1", "Input in (-1, 1)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Activation Functions (often in core torch as well) ---
    
    contracts.append(FunctionContract(
        name="sigmoid",
        module="torch",
        description="Sigmoid activation",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="relu",
        module="torch",
        description="ReLU activation",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="relu_",
        module="torch",
        description="In-place ReLU",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
        modifies_input=True,
    ))
    
    contracts.append(FunctionContract(
        name="softmax",
        module="torch",
        description="Softmax (output sums to 1)",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Absolute Value and Sign ---
    
    contracts.append(FunctionContract(
        name="abs",
        module="torch",
        description="Absolute value",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="absolute",
        module="torch",
        description="Absolute value (alias)",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="sign",
        module="torch",
        description="Sign function (-1, 0, or 1)",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="sgn",
        module="torch",
        description="Sign function for complex",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="signbit",
        module="torch",
        description="Returns True if sign bit is set",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Rounding ---
    
    contracts.append(FunctionContract(
        name="ceil",
        module="torch",
        description="Ceiling function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="floor",
        module="torch",
        description="Floor function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="round",
        module="torch",
        description="Round to nearest integer",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="trunc",
        module="torch",
        description="Truncate to integer",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="frac",
        module="torch",
        description="Fractional part",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Clipping and Bounding ---
    
    contracts.append(FunctionContract(
        name="clamp",
        module="torch",
        description="Clamp values to range",
        preserves_device=True,
        preserves_shape=True,
        # Return interval depends on min/max args
    ))
    
    contracts.append(FunctionContract(
        name="clip",
        module="torch",
        description="Clip values (alias for clamp)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="clamp_min",
        module="torch",
        description="Clamp to minimum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="clamp_max",
        module="torch",
        description="Clamp to maximum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Arithmetic ---
    
    contracts.append(FunctionContract(
        name="add",
        module="torch",
        description="Element-wise addition",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,  # after broadcast
    ))
    
    contracts.append(FunctionContract(
        name="sub",
        module="torch",
        description="Element-wise subtraction",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="subtract",
        module="torch",
        description="Element-wise subtraction (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="mul",
        module="torch",
        description="Element-wise multiplication",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="multiply",
        module="torch",
        description="Element-wise multiplication (alias)",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="div",
        module="torch",
        description="Element-wise division",
        preconditions=[Precondition("divisor != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="divide",
        module="torch",
        description="Element-wise division (alias)",
        preconditions=[Precondition("divisor != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="true_divide",
        module="torch",
        description="True division",
        preconditions=[Precondition("divisor != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="floor_divide",
        module="torch",
        description="Floor division",
        preconditions=[Precondition("divisor != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="fmod",
        module="torch",
        description="Element-wise remainder (C-style)",
        preconditions=[Precondition("divisor != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="remainder",
        module="torch",
        description="Element-wise remainder (Python-style)",
        preconditions=[Precondition("divisor != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="neg",
        module="torch",
        description="Negation",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="negative",
        module="torch",
        description="Negation (alias)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="positive",
        module="torch",
        description="Positive (no-op for reals)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="reciprocal",
        module="torch",
        description="1/x",
        preconditions=[Precondition("x != 0", "Input must be non-zero")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- FMA and Special Arithmetic ---
    
    contracts.append(FunctionContract(
        name="addcmul",
        module="torch",
        description="input + value * tensor1 * tensor2",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="addcdiv",
        module="torch",
        description="input + value * tensor1 / tensor2",
        preconditions=[Precondition("tensor2 != 0", "Divisor must be non-zero")],
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="lerp",
        module="torch",
        description="Linear interpolation",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="fma",
        module="torch",
        description="Fused multiply-add",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Error Function Family ---
    
    contracts.append(FunctionContract(
        name="erf",
        module="torch",
        description="Error function",
        return_interval=Interval(-1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfc",
        module="torch",
        description="Complementary error function",
        return_interval=Interval(0.0, 2.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfinv",
        module="torch",
        description="Inverse error function",
        preconditions=[Precondition("-1 < x < 1", "Input in (-1, 1)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="erfcinv",
        module="torch",
        description="Inverse complementary error function",
        preconditions=[Precondition("0 < x < 2", "Input in (0, 2)")],
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Gamma Family ---
    
    contracts.append(FunctionContract(
        name="lgamma",
        module="torch",
        description="Log-gamma function",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="digamma",
        module="torch",
        description="Digamma function (psi)",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="polygamma",
        module="torch",
        description="n-th derivative of digamma",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="mvlgamma",
        module="torch",
        description="Multivariate log-gamma",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Bessel Functions ---
    
    contracts.append(FunctionContract(
        name="i0",
        module="torch",
        description="Modified Bessel I0",
        return_interval=Interval(1.0, float('inf')),
        guarantees_positive=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="i0e",
        module="torch",
        description="Exponentially scaled modified Bessel I0",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="i1",
        module="torch",
        description="Modified Bessel I1",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="i1e",
        module="torch",
        description="Exponentially scaled modified Bessel I1",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Special Values ---
    
    contracts.append(FunctionContract(
        name="nan_to_num",
        module="torch",
        description="Replace NaN/Inf with finite values",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isnan",
        module="torch",
        description="Test for NaN",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isinf",
        module="torch",
        description="Test for infinity",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isposinf",
        module="torch",
        description="Test for positive infinity",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isneginf",
        module="torch",
        description="Test for negative infinity",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isfinite",
        module="torch",
        description="Test for finite values",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isreal",
        module="torch",
        description="Test for real values",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Complex Number Operations ---
    
    contracts.append(FunctionContract(
        name="real",
        module="torch",
        description="Real part of complex tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="imag",
        module="torch",
        description="Imaginary part of complex tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="conj",
        module="torch",
        description="Complex conjugate",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="conj_physical",
        module="torch",
        description="Physical complex conjugate",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="angle",
        module="torch",
        description="Phase angle of complex tensor",
        return_interval=Interval(-math.pi, math.pi),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="polar",
        module="torch",
        description="Create complex from magnitude/angle",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="view_as_real",
        module="torch",
        description="View complex as real pairs",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="view_as_complex",
        module="torch",
        description="View real pairs as complex",
        preserves_device=True,
    ))
    
    # =========================================================================
    # REDUCTION OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="sum",
        module="torch",
        description="Sum of elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="prod",
        module="torch",
        description="Product of elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="mean",
        module="torch",
        description="Mean of elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="median",
        module="torch",
        description="Median of elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="nanmedian",
        module="torch",
        description="Median ignoring NaN",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="mode",
        module="torch",
        description="Mode of elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="std",
        module="torch",
        description="Standard deviation",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="std_mean",
        module="torch",
        description="Std and mean together",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="var",
        module="torch",
        description="Variance",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="var_mean",
        module="torch",
        description="Variance and mean together",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="max",
        module="torch",
        description="Maximum value(s)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="min",
        module="torch",
        description="Minimum value(s)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="amax",
        module="torch",
        description="Maximum along dimension",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="amin",
        module="torch",
        description="Minimum along dimension",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="aminmax",
        module="torch",
        description="Min and max together",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="argmax",
        module="torch",
        description="Index of maximum",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="argmin",
        module="torch",
        description="Index of minimum",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="all",
        module="torch",
        description="Test if all True",
        return_dtype=DType.BOOL,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="any",
        module="torch",
        description="Test if any True",
        return_dtype=DType.BOOL,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="count_nonzero",
        module="torch",
        description="Count non-zero elements",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="logsumexp",
        module="torch",
        description="log(sum(exp(x)))",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="norm",
        module="torch",
        description="Vector/matrix norm",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="dist",
        module="torch",
        description="p-norm of difference",
        requires_same_device=True,
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="nansum",
        module="torch",
        description="Sum ignoring NaN",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="nanmean",
        module="torch",
        description="Mean ignoring NaN",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cumsum",
        module="torch",
        description="Cumulative sum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="cumprod",
        module="torch",
        description="Cumulative product",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="cummax",
        module="torch",
        description="Cumulative maximum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="cummin",
        module="torch",
        description="Cumulative minimum",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="logcumsumexp",
        module="torch",
        description="Cumulative log-sum-exp",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # --- Histograms ---
    
    contracts.append(FunctionContract(
        name="histc",
        module="torch",
        description="Histogram (legacy)",
        return_interval=Interval.non_negative(),
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="histogram",
        module="torch",
        description="Histogram",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="histogramdd",
        module="torch",
        description="Multi-dimensional histogram",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="bincount",
        module="torch",
        description="Count integer occurrences",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
        preserves_device=True,
    ))
    
    # =========================================================================
    # COMPARISON OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="eq",
        module="torch",
        description="Element-wise equality",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="equal",
        module="torch",
        description="Tensor equality",
        return_dtype=DType.BOOL,
        requires_same_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ne",
        module="torch",
        description="Element-wise not equal",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="not_equal",
        module="torch",
        description="Element-wise not equal (alias)",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="lt",
        module="torch",
        description="Element-wise less than",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="less",
        module="torch",
        description="Element-wise less than (alias)",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="le",
        module="torch",
        description="Element-wise less or equal",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="less_equal",
        module="torch",
        description="Element-wise less or equal (alias)",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="gt",
        module="torch",
        description="Element-wise greater than",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="greater",
        module="torch",
        description="Element-wise greater than (alias)",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="ge",
        module="torch",
        description="Element-wise greater or equal",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="greater_equal",
        module="torch",
        description="Element-wise greater or equal (alias)",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="maximum",
        module="torch",
        description="Element-wise maximum",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="minimum",
        module="torch",
        description="Element-wise minimum",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="fmax",
        module="torch",
        description="Element-wise max ignoring NaN",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="fmin",
        module="torch",
        description="Element-wise min ignoring NaN",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="isclose",
        module="torch",
        description="Element-wise close comparison",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="allclose",
        module="torch",
        description="All elements close",
        return_dtype=DType.BOOL,
        requires_same_device=True,
    ))
    
    # --- Sorting and Selection ---
    
    contracts.append(FunctionContract(
        name="sort",
        module="torch",
        description="Sort tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="argsort",
        module="torch",
        description="Indices that would sort",
        return_dtype=DType.INT64,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="msort",
        module="torch",
        description="Sort along first dimension",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="topk",
        module="torch",
        description="Top-k values and indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="kthvalue",
        module="torch",
        description="k-th smallest value",
        preserves_device=True,
    ))
    
    # =========================================================================
    # TENSOR CREATION
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="tensor",
        module="torch",
        description="Create tensor from data",
    ))
    
    contracts.append(FunctionContract(
        name="zeros",
        module="torch",
        description="Create zero tensor",
        return_interval=Interval(0.0, 0.0),
    ))
    
    contracts.append(FunctionContract(
        name="zeros_like",
        module="torch",
        description="Zeros with same shape/device",
        return_interval=Interval(0.0, 0.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="ones",
        module="torch",
        description="Create ones tensor",
        return_interval=Interval(1.0, 1.0),
    ))
    
    contracts.append(FunctionContract(
        name="ones_like",
        module="torch",
        description="Ones with same shape/device",
        return_interval=Interval(1.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="full",
        module="torch",
        description="Create tensor filled with value",
    ))
    
    contracts.append(FunctionContract(
        name="full_like",
        module="torch",
        description="Full with same shape/device",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="empty",
        module="torch",
        description="Create uninitialized tensor",
    ))
    
    contracts.append(FunctionContract(
        name="empty_like",
        module="torch",
        description="Empty with same shape/device",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="empty_strided",
        module="torch",
        description="Empty with specific strides",
    ))
    
    contracts.append(FunctionContract(
        name="arange",
        module="torch",
        description="Create range tensor",
    ))
    
    contracts.append(FunctionContract(
        name="range",
        module="torch",
        description="Create range tensor (deprecated)",
    ))
    
    contracts.append(FunctionContract(
        name="linspace",
        module="torch",
        description="Create linearly spaced tensor",
    ))
    
    contracts.append(FunctionContract(
        name="logspace",
        module="torch",
        description="Create logarithmically spaced tensor",
        return_interval=Interval.positive(),
        guarantees_positive=True,
    ))
    
    contracts.append(FunctionContract(
        name="eye",
        module="torch",
        description="Create identity matrix",
        return_interval=Interval(0.0, 1.0),
    ))
    
    contracts.append(FunctionContract(
        name="diag",
        module="torch",
        description="Create diagonal matrix or extract diagonal",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="diagflat",
        module="torch",
        description="Create tensor with diagonal from input",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="tril",
        module="torch",
        description="Lower triangular",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="triu",
        module="torch",
        description="Upper triangular",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="tril_indices",
        module="torch",
        description="Indices for lower triangular",
        return_dtype=DType.INT64,
    ))
    
    contracts.append(FunctionContract(
        name="triu_indices",
        module="torch",
        description="Indices for upper triangular",
        return_dtype=DType.INT64,
    ))
    
    # --- Random ---
    
    contracts.append(FunctionContract(
        name="rand",
        module="torch",
        description="Uniform random [0, 1)",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
    ))
    
    contracts.append(FunctionContract(
        name="rand_like",
        module="torch",
        description="Uniform random with same shape/device",
        return_interval=Interval(0.0, 1.0),
        guarantees_non_negative=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="randn",
        module="torch",
        description="Standard normal random",
    ))
    
    contracts.append(FunctionContract(
        name="randn_like",
        module="torch",
        description="Normal random with same shape/device",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="randint",
        module="torch",
        description="Random integers",
        return_dtype=DType.INT64,
    ))
    
    contracts.append(FunctionContract(
        name="randint_like",
        module="torch",
        description="Random integers with same shape/device",
        return_dtype=DType.INT64,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="randperm",
        module="torch",
        description="Random permutation",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
    ))
    
    contracts.append(FunctionContract(
        name="bernoulli",
        module="torch",
        description="Bernoulli random",
        return_interval=Interval(0.0, 1.0),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="multinomial",
        module="torch",
        description="Multinomial samples",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="normal",
        module="torch",
        description="Normal distribution samples",
    ))
    
    contracts.append(FunctionContract(
        name="poisson",
        module="torch",
        description="Poisson samples",
        return_interval=Interval.non_negative(),
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # TENSOR MANIPULATION
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="cat",
        module="torch",
        description="Concatenate tensors",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="concat",
        module="torch",
        description="Concatenate tensors (alias)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="concatenate",
        module="torch",
        description="Concatenate tensors (alias)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="stack",
        module="torch",
        description="Stack tensors along new dimension",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="hstack",
        module="torch",
        description="Horizontal stack",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="vstack",
        module="torch",
        description="Vertical stack",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="dstack",
        module="torch",
        description="Depth stack",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="row_stack",
        module="torch",
        description="Row stack (alias for vstack)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="column_stack",
        module="torch",
        description="Column stack",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="split",
        module="torch",
        description="Split tensor",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="chunk",
        module="torch",
        description="Split into chunks",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="tensor_split",
        module="torch",
        description="Split tensor",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="hsplit",
        module="torch",
        description="Horizontal split",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="vsplit",
        module="torch",
        description="Vertical split",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="dsplit",
        module="torch",
        description="Depth split",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="reshape",
        module="torch",
        description="Reshape tensor",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="view",
        module="torch",
        description="View tensor with different shape",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="flatten",
        module="torch",
        description="Flatten tensor",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ravel",
        module="torch",
        description="Flatten to 1D",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="unflatten",
        module="torch",
        description="Unflatten dimension",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="squeeze",
        module="torch",
        description="Remove size-1 dimensions",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="unsqueeze",
        module="torch",
        description="Add dimension of size 1",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="transpose",
        module="torch",
        description="Transpose dimensions",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="t",
        module="torch",
        description="2D transpose",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="permute",
        module="torch",
        description="Permute dimensions",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="movedim",
        module="torch",
        description="Move dimensions",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="moveaxis",
        module="torch",
        description="Move axes (alias)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="swapaxes",
        module="torch",
        description="Swap axes",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="swapdims",
        module="torch",
        description="Swap dimensions (alias)",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="narrow",
        module="torch",
        description="Narrow along dimension",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="narrow_copy",
        module="torch",
        description="Narrow with copy",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="select",
        module="torch",
        description="Select slice along dimension",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="repeat_interleave",
        module="torch",
        description="Repeat elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="tile",
        module="torch",
        description="Tile tensor",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="broadcast_to",
        module="torch",
        description="Broadcast to shape",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="broadcast_tensors",
        module="torch",
        description="Broadcast multiple tensors",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="broadcast_shapes",
        module="torch",
        description="Compute broadcast shape",
    ))
    
    contracts.append(FunctionContract(
        name="expand_as",
        module="torch",
        description="Expand to match tensor",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="flip",
        module="torch",
        description="Flip along dimensions",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="fliplr",
        module="torch",
        description="Flip left-right",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="flipud",
        module="torch",
        description="Flip up-down",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="rot90",
        module="torch",
        description="Rotate 90 degrees",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="roll",
        module="torch",
        description="Roll tensor",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="unbind",
        module="torch",
        description="Remove dimension and return tuple",
        preserves_device=True,
    ))
    
    # --- Indexing ---
    
    contracts.append(FunctionContract(
        name="index_select",
        module="torch",
        description="Select along dimension with indices",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="masked_select",
        module="torch",
        description="Select elements with mask",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="gather",
        module="torch",
        description="Gather values along dimension",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="scatter",
        module="torch",
        description="Scatter values along dimension",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="scatter_add",
        module="torch",
        description="Scatter add values",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="scatter_reduce",
        module="torch",
        description="Scatter with reduction",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="take",
        module="torch",
        description="Take elements by indices",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="take_along_dim",
        module="torch",
        description="Take along dimension",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="where",
        module="torch",
        description="Conditional select",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="nonzero",
        module="torch",
        description="Indices of non-zero elements",
        return_dtype=DType.INT64,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="index_add",
        module="torch",
        description="Add to tensor with indices",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="index_copy",
        module="torch",
        description="Copy to tensor with indices",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="index_fill",
        module="torch",
        description="Fill tensor with indices",
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="index_put",
        module="torch",
        description="Put values at indices",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="masked_fill",
        module="torch",
        description="Fill with mask",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="masked_scatter",
        module="torch",
        description="Scatter with mask",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # MATRIX/LINEAR ALGEBRA (basic operations in torch.*)
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="mm",
        module="torch",
        description="Matrix multiplication",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="bmm",
        module="torch",
        description="Batched matrix multiplication",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="matmul",
        module="torch",
        description="General matrix product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="mv",
        module="torch",
        description="Matrix-vector product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="dot",
        module="torch",
        description="Dot product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="vdot",
        module="torch",
        description="Vector dot product with conjugate",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="inner",
        module="torch",
        description="Inner product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="outer",
        module="torch",
        description="Outer product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cross",
        module="torch",
        description="Cross product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="tensordot",
        module="torch",
        description="Tensor contraction",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="einsum",
        module="torch",
        description="Einstein summation",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="kron",
        module="torch",
        description="Kronecker product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="addr",
        module="torch",
        description="beta * input + alpha * outer(v1, v2)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="addmm",
        module="torch",
        description="beta * input + alpha * (m1 @ m2)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="addmv",
        module="torch",
        description="beta * input + alpha * (m @ v)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="addbmm",
        module="torch",
        description="Batched addmm",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="baddbmm",
        module="torch",
        description="Batched addmm element-wise",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="ger",
        module="torch",
        description="Outer product (deprecated alias)",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="trace",
        module="torch",
        description="Matrix trace",
        preserves_device=True,
    ))
    
    # =========================================================================
    # BITWISE OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="bitwise_not",
        module="torch",
        description="Bitwise NOT",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(FunctionContract(
        name="bitwise_and",
        module="torch",
        description="Bitwise AND",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="bitwise_or",
        module="torch",
        description="Bitwise OR",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="bitwise_xor",
        module="torch",
        description="Bitwise XOR",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="bitwise_left_shift",
        module="torch",
        description="Bitwise left shift",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="bitwise_right_shift",
        module="torch",
        description="Bitwise right shift",
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # LOGICAL OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="logical_not",
        module="torch",
        description="Logical NOT",
        return_dtype=DType.BOOL,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="logical_and",
        module="torch",
        description="Logical AND",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="logical_or",
        module="torch",
        description="Logical OR",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    contracts.append(FunctionContract(
        name="logical_xor",
        module="torch",
        description="Logical XOR",
        return_dtype=DType.BOOL,
        requires_same_device=True,
        preserves_device=True,
        preserves_shape=True,
    ))
    
    # =========================================================================
    # TYPE OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="is_tensor",
        module="torch",
        description="Test if tensor",
        return_dtype=DType.BOOL,
    ))
    
    contracts.append(FunctionContract(
        name="is_storage",
        module="torch",
        description="Test if storage",
        return_dtype=DType.BOOL,
    ))
    
    contracts.append(FunctionContract(
        name="is_complex",
        module="torch",
        description="Test if complex dtype",
        return_dtype=DType.BOOL,
    ))
    
    contracts.append(FunctionContract(
        name="is_conj",
        module="torch",
        description="Test if conjugate view",
        return_dtype=DType.BOOL,
    ))
    
    contracts.append(FunctionContract(
        name="is_floating_point",
        module="torch",
        description="Test if floating point",
        return_dtype=DType.BOOL,
    ))
    
    contracts.append(FunctionContract(
        name="is_nonzero",
        module="torch",
        description="Test if single non-zero element",
        return_dtype=DType.BOOL,
    ))
    
    contracts.append(FunctionContract(
        name="numel",
        module="torch",
        description="Number of elements",
        return_interval=Interval.non_negative(),
        return_dtype=DType.INT64,
    ))
    
    # =========================================================================
    # DEVICE OPERATIONS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="cuda",
        module="torch",
        description="Copy to CUDA device",
        # Changes device to CUDA
    ))
    
    contracts.append(FunctionContract(
        name="cpu",
        module="torch",
        description="Copy to CPU",
        # Changes device to CPU
    ))
    
    contracts.append(FunctionContract(
        name="to",
        module="torch",
        description="Move to device/dtype",
    ))
    
    # =========================================================================
    # CLONE/COPY
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="clone",
        module="torch",
        description="Clone tensor",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(FunctionContract(
        name="contiguous",
        module="torch",
        description="Make contiguous",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    contracts.append(FunctionContract(
        name="detach",
        module="torch",
        description="Detach from computation graph",
        preserves_device=True,
        preserves_shape=True,
        preserves_dtype=True,
    ))
    
    # =========================================================================
    # MISCELLANEOUS
    # =========================================================================
    
    contracts.append(FunctionContract(
        name="unique",
        module="torch",
        description="Unique elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="unique_consecutive",
        module="torch",
        description="Unique consecutive elements",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="searchsorted",
        module="torch",
        description="Find indices for sorted insert",
        return_dtype=DType.INT64,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="bucketize",
        module="torch",
        description="Bucketize values",
        return_dtype=DType.INT64,
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cdist",
        module="torch",
        description="Pairwise distance",
        requires_same_device=True,
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="pdist",
        module="torch",
        description="Pairwise distances",
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="cartesian_prod",
        module="torch",
        description="Cartesian product",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="combinations",
        module="torch",
        description="Combinations",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="meshgrid",
        module="torch",
        description="Create meshgrid",
        requires_same_device=True,
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="stft",
        module="torch",
        description="Short-time Fourier transform",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="istft",
        module="torch",
        description="Inverse STFT",
        preserves_device=True,
    ))
    
    contracts.append(FunctionContract(
        name="bartlett_window",
        module="torch",
        description="Bartlett window",
        return_interval=Interval(0.0, 1.0),
    ))
    
    contracts.append(FunctionContract(
        name="blackman_window",
        module="torch",
        description="Blackman window",
        return_interval=Interval(-0.01, 1.0),
    ))
    
    contracts.append(FunctionContract(
        name="hamming_window",
        module="torch",
        description="Hamming window",
        return_interval=Interval(0.0, 1.0),
    ))
    
    contracts.append(FunctionContract(
        name="hann_window",
        module="torch",
        description="Hann window",
        return_interval=Interval(0.0, 1.0),
    ))
    
    contracts.append(FunctionContract(
        name="kaiser_window",
        module="torch",
        description="Kaiser window",
        return_interval=Interval(0.0, 1.0),
    ))
    
    # Register all contracts
    bulk_register(contracts, registry)
