"""
PyTorch Library Contracts - Barrier Theory Implementation

Semantic specifications for PyTorch functions to enable precise bug detection.
Includes value interval tracking for deferred barrier checking.

Key insight: Functions like cosine_similarity return values in [-1, 1].
This enables proving that cosine_similarity(x, y) - 3 can never be zero,
because the result interval is [-4, -2] which doesn't contain 0.
"""

from __future__ import annotations

from .base import (
    BoundsSpec,
    DimSource,
    DimSpec,
    ExceptionSpec,
    Interval,
    LibraryContract,
    Nullability,
    Postcondition,
    Precondition,
    ShapeSpec,
    TaintBehavior,
    TaintSpec,
    TypeSpec,
    register_contract,
)


def _type(name: str, *generics: str, optional: bool = False) -> TypeSpec:
    """Helper to create TypeSpec."""
    return TypeSpec(base_type=name, generic_args=list(generics), is_optional=optional)


def _tensor_type() -> TypeSpec:
    """Create Tensor type."""
    return _type("torch.Tensor")


def _shape_from_size_args() -> ShapeSpec:
    """Shape comes from *size arguments."""
    return ShapeSpec(dims=[DimSpec(source=DimSource.ARG, value="size")])


def _shape_same_as(arg: str) -> ShapeSpec:
    """Shape is same as input arg."""
    return ShapeSpec.same_as_input(arg)


# =============================================================================
# TENSOR CREATION FUNCTIONS
# =============================================================================

TORCH_TENSOR_CREATION = [
    LibraryContract(
        module="torch",
        function="tensor",
        signature="(data, *, dtype=None, device=None, requires_grad=False) -> Tensor",
        description="Create tensor from data (list, tuple, numpy array, etc.)",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # Shape is inferred from data structure
        return_shape=ShapeSpec(dims=[DimSpec(source=DimSource.ARG_SHAPE, value="data")]),
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="zeros",
        signature="(*size, out=None, dtype=None, device=None) -> Tensor",
        description="Create tensor filled with zeros",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_from_size_args(),
        bounds_info=BoundsSpec(equals_value=0.0),
        postconditions=[
            Postcondition("all elements are 0", "value_constraint"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="ones",
        signature="(*size, out=None, dtype=None, device=None) -> Tensor",
        description="Create tensor filled with ones",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_from_size_args(),
        bounds_info=BoundsSpec(equals_value=1.0),
        postconditions=[
            Postcondition("all elements are 1", "value_constraint"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="empty",
        signature="(*size, out=None, dtype=None, device=None) -> Tensor",
        description="Create uninitialized tensor",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_from_size_args(),
        # Note: values are uninitialized, could be anything
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="randn",
        signature="(*size, out=None, dtype=None, device=None) -> Tensor",
        description="Create tensor with random normal values",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_from_size_args(),
        # Values are ~N(0,1), but technically unbounded
        bounds_info=BoundsSpec(finite=True),
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="rand",
        signature="(*size, out=None, dtype=None, device=None) -> Tensor",
        description="Create tensor with random uniform [0, 1) values",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_from_size_args(),
        bounds_info=BoundsSpec(min_value=0.0, max_value=1.0, non_negative=True),
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="randint",
        signature="(low, high, size, *, dtype=None, device=None) -> Tensor",
        description="Create tensor with random integers in [low, high)",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[DimSpec(source=DimSource.ARG, value="size")]),
        bounds_info=BoundsSpec(min_value="low", max_value="high - 1", integer_only=True),
        preconditions=[
            Precondition("low < high", "VALUE_ERROR", check_expr="low < high"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="arange",
        signature="(start, end=None, step=1, *, dtype=None, device=None) -> Tensor",
        description="Create 1D tensor with values from start to end",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[
            DimSpec.computed("ceil((end - start) / step)", min_val=0)
        ]),
        bounds_info=BoundsSpec(min_value="start", max_value="end - step"),
        preconditions=[
            Precondition.non_zero_arg(2, "step"),  # step != 0
            Precondition(
                "(end - start) / step >= 0",
                "VALUE_ERROR",
                check_expr="(end - start) * step >= 0"
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="linspace",
        signature="(start, end, steps, *, dtype=None, device=None) -> Tensor",
        description="Create 1D tensor with evenly spaced values",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[DimSpec.from_arg("steps")]),
        preconditions=[
            Precondition("steps >= 0", "VALUE_ERROR", arg_indices=[2]),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="eye",
        signature="(n, m=None, *, dtype=None, device=None) -> Tensor",
        description="Create 2D identity matrix",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[
            DimSpec.from_arg("n"),
            DimSpec.from_arg("m if m is not None else n"),
        ]),
        bounds_info=BoundsSpec(min_value=0.0, max_value=1.0),
        preconditions=[
            Precondition("n >= 0", "VALUE_ERROR", arg_indices=[0]),
        ],
        pure=True,
    ),
    
    # Like functions (shape from input)
    LibraryContract(
        module="torch",
        function="zeros_like",
        signature="(input, *, dtype=None, device=None) -> Tensor",
        description="Create zeros tensor with same shape as input",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(equals_value=0.0),
        preconditions=[
            Precondition.non_null_arg(0, "input"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="ones_like",
        signature="(input, *, dtype=None, device=None) -> Tensor",
        description="Create ones tensor with same shape as input",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(equals_value=1.0),
        preconditions=[
            Precondition.non_null_arg(0, "input"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="empty_like",
        signature="(input, *, dtype=None, device=None) -> Tensor",
        description="Create uninitialized tensor with same shape as input",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        preconditions=[
            Precondition.non_null_arg(0, "input"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="rand_like",
        signature="(input, *, dtype=None, device=None) -> Tensor",
        description="Create random [0,1) tensor with same shape as input",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(min_value=0.0, max_value=1.0),
        preconditions=[
            Precondition.non_null_arg(0, "input"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="randn_like",
        signature="(input, *, dtype=None, device=None) -> Tensor",
        description="Create random normal tensor with same shape as input",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        preconditions=[
            Precondition.non_null_arg(0, "input"),
        ],
        pure=True,
    ),
]


# =============================================================================
# TENSOR METHODS - INDEXING AND SLICING
# =============================================================================

TORCH_TENSOR_INDEXING = [
    LibraryContract(
        module="torch.Tensor",
        function="__getitem__",
        signature="(self, index) -> Tensor | Scalar",
        description="Index into tensor",
        return_type=_tensor_type(),  # Or scalar for 0-d result
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "index is within bounds for all dimensions",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        exceptions=[
            ExceptionSpec("IndexError", "index out of bounds", is_bug=True),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__setitem__",
        signature="(self, index, value) -> None",
        description="Set tensor values at index",
        return_type=_type("None"),
        return_nullability=Nullability.ALWAYS,
        preconditions=[
            Precondition(
                "index is within bounds for all dimensions",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        exceptions=[
            ExceptionSpec("IndexError", "index out of bounds", is_bug=True),
        ],
        modifies_args=[0],  # Modifies self
        pure=False,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="index_select",
        signature="(self, dim, index) -> Tensor",
        description="Select elements along dimension using index tensor",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[1],
                check_expr="-self.ndim <= dim < self.ndim"
            ),
            Precondition(
                "all indices in index are valid",
                "BOUNDS",
                arg_indices=[2],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="gather",
        signature="(self, dim, index) -> Tensor",
        description="Gather values along dimension using index tensor",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[1],
            ),
            Precondition(
                "index.shape matches self.shape except at dim",
                "VALUE_ERROR",
                arg_indices=[2],
            ),
        ],
        pure=True,
    ),
]


# =============================================================================
# TENSOR METHODS - SHAPE OPERATIONS
# =============================================================================

TORCH_TENSOR_SHAPE = [
    LibraryContract(
        module="torch.Tensor",
        function="view",
        signature="(self, *shape) -> Tensor",
        description="Return tensor with new shape (must have same number of elements)",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[DimSpec(source=DimSource.ARG, value="shape")]),
        preconditions=[
            Precondition(
                "product of new shape equals product of old shape",
                "VALUE_ERROR",
                check_expr="product(shape) == self.numel() or -1 in shape"
            ),
        ],
        exceptions=[
            ExceptionSpec("RuntimeError", "shape doesn't match numel()", is_bug=True),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="reshape",
        signature="(self, *shape) -> Tensor",
        description="Return tensor with new shape",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[DimSpec(source=DimSource.ARG, value="shape")]),
        preconditions=[
            Precondition(
                "product of new shape equals product of old shape",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="squeeze",
        signature="(self, dim=None) -> Tensor",
        description="Remove dimensions of size 1",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # Shape: removes dims where size == 1
        preconditions=[
            Precondition(
                "dim is valid if specified",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="unsqueeze",
        signature="(self, dim) -> Tensor",
        description="Add dimension of size 1 at position",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "-self.ndim - 1 <= dim <= self.ndim",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="flatten",
        signature="(self, start_dim=0, end_dim=-1) -> Tensor",
        description="Flatten dimensions from start_dim to end_dim",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "start_dim and end_dim are valid dimensions",
                "BOUNDS",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="transpose",
        signature="(self, dim0, dim1) -> Tensor",
        description="Swap two dimensions",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "dim0 is valid dimension",
                "BOUNDS",
                arg_indices=[1],
            ),
            Precondition(
                "dim1 is valid dimension",
                "BOUNDS",
                arg_indices=[2],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="permute",
        signature="(self, *dims) -> Tensor",
        description="Permute dimensions",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "len(dims) == self.ndim",
                "VALUE_ERROR",
            ),
            Precondition(
                "dims is a valid permutation of range(self.ndim)",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="expand",
        signature="(self, *sizes) -> Tensor",
        description="Expand tensor to larger size",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=ShapeSpec(dims=[DimSpec(source=DimSource.ARG, value="sizes")]),
        preconditions=[
            Precondition(
                "sizes are compatible with broadcasting",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="repeat",
        signature="(self, *repeats) -> Tensor",
        description="Repeat tensor along dimensions",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "len(repeats) >= self.ndim",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
]


# =============================================================================
# TENSOR METHODS - REDUCTION OPERATIONS
# =============================================================================

TORCH_TENSOR_REDUCTION = [
    LibraryContract(
        module="torch.Tensor",
        function="sum",
        signature="(self, dim=None, keepdim=False) -> Tensor",
        description="Sum of elements",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "dim is valid dimension if specified",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="mean",
        signature="(self, dim=None, keepdim=False) -> Tensor",
        description="Mean of elements",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "dim is valid dimension if specified",
                "BOUNDS",
                arg_indices=[1],
            ),
            Precondition(
                "tensor has at least one element (or dim has size > 0)",
                "DIV_ZERO",
                severity="MEDIUM",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="max",
        signature="(self, dim=None, keepdim=False) -> Tensor | tuple",
        description="Maximum value(s)",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "tensor is not empty",
                "VALUE_ERROR",
            ),
            Precondition(
                "dim is valid dimension if specified",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="min",
        signature="(self, dim=None, keepdim=False) -> Tensor | tuple",
        description="Minimum value(s)",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "tensor is not empty",
                "VALUE_ERROR",
            ),
            Precondition(
                "dim is valid dimension if specified",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="argmax",
        signature="(self, dim=None, keepdim=False) -> Tensor",
        description="Index of maximum value",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # Return values are valid indices into the tensor
        bounds_info=BoundsSpec(non_negative=True, integer_only=True),
        preconditions=[
            Precondition(
                "tensor is not empty",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="argmin",
        signature="(self, dim=None, keepdim=False) -> Tensor",
        description="Index of minimum value",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True, integer_only=True),
        preconditions=[
            Precondition(
                "tensor is not empty",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="item",
        signature="(self) -> number",
        description="Get Python scalar from single-element tensor",
        return_type=TypeSpec(base_type="number", union_types=["int", "float"]),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "self.numel() == 1",
                "VALUE_ERROR",
                check_expr="self.numel() == 1"
            ),
        ],
        exceptions=[
            ExceptionSpec("RuntimeError", "tensor has more than one element", is_bug=True),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="tolist",
        signature="(self) -> list",
        description="Convert tensor to nested Python list",
        return_type=_type("list"),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
]


# =============================================================================
# TENSOR METHODS - ARITHMETIC WITH DIVISION
# =============================================================================

TORCH_TENSOR_ARITHMETIC = [
    LibraryContract(
        module="torch.Tensor",
        function="__truediv__",
        signature="(self, other) -> Tensor",
        description="Element-wise division",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("self"),  # After broadcasting
        preconditions=[
            Precondition(
                "other != 0 (element-wise)",
                "DIV_ZERO",
                arg_indices=[1],
                severity="MEDIUM",  # May be intentional for inf
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__floordiv__",
        signature="(self, other) -> Tensor",
        description="Element-wise floor division",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "other != 0 (element-wise)",
                "DIV_ZERO",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="div",
        signature="(self, other, *, rounding_mode=None) -> Tensor",
        description="Element-wise division",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "other != 0 (element-wise)",
                "DIV_ZERO",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="div",
        signature="(input, other, *, rounding_mode=None) -> Tensor",
        description="Element-wise division",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "other != 0 (element-wise)",
                "DIV_ZERO",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
]


# =============================================================================
# TENSOR METHODS - NORMALIZATION
# =============================================================================

TORCH_TENSOR_NORM = [
    LibraryContract(
        module="torch.Tensor",
        function="norm",
        signature="(self, p=2, dim=None, keepdim=False) -> Tensor",
        description="Compute p-norm",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),  # Norms are always >= 0
        preconditions=[
            Precondition(
                "dim is valid dimension if specified",
                "BOUNDS",
                arg_indices=[2],
            ),
        ],
        postconditions=[
            Postcondition("result >= 0", "value_constraint"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="norm",
        signature="(input, p=2, dim=None, keepdim=False) -> Tensor",
        description="Compute p-norm",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),
        pure=True,
    ),
    
    LibraryContract(
        module="torch.linalg",
        function="norm",
        signature="(A, ord=None, dim=None, keepdim=False) -> Tensor",
        description="Compute matrix or vector norm",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),
        pure=True,
    ),
    
    LibraryContract(
        module="torch.nn.functional",
        function="normalize",
        signature="(input, p=2, dim=1, eps=1e-12) -> Tensor",
        description="Normalize along dimension",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        # Note: eps prevents div by zero
        postconditions=[
            Postcondition("output.norm(p, dim) ≈ 1 (where input norm > eps)", "value_constraint"),
        ],
        pure=True,
    ),
]


# =============================================================================
# TORCH I/O - LOADING AND SAVING
# =============================================================================

TORCH_IO = [
    LibraryContract(
        module="torch",
        function="load",
        signature="(f, map_location=None, pickle_module=pickle, *, weights_only=False) -> Any",
        description="Load object from file using pickle",
        return_type=_type("Any"),
        return_nullability=Nullability.NEVER,  # Raises on failure
        preconditions=[
            Precondition(
                "file exists and is readable",
                "FILE_NOT_FOUND",
                arg_indices=[0],
            ),
        ],
        exceptions=[
            ExceptionSpec("FileNotFoundError", "file doesn't exist", is_bug=True),
            ExceptionSpec("pickle.UnpicklingError", "corrupt file", is_bug=False),
        ],
        taint_spec=TaintSpec(
            behavior=TaintBehavior.SINK,
            sink_type="UNSAFE_DESERIALIZATION",
            sink_arg_indices=[0],
        ),
        unsafe_with_user_input=True,
        pure=True,  # Doesn't modify anything, but reads file
    ),
    
    LibraryContract(
        module="torch",
        function="save",
        signature="(obj, f, pickle_module=pickle, pickle_protocol=DEFAULT_PROTOCOL) -> None",
        description="Save object to file using pickle",
        return_type=_type("None"),
        return_nullability=Nullability.ALWAYS,
        pure=False,  # Writes to file
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="load_state_dict",
        signature="(self, state_dict, strict=True) -> None",
        description="Load state dict into module",
        return_type=_type("None"),
        return_nullability=Nullability.ALWAYS,
        modifies_args=[0],
        # Security: state_dict could be malicious if from untrusted source
        taint_spec=TaintSpec(
            behavior=TaintBehavior.SINK,
            sink_type="UNSAFE_DESERIALIZATION",
            sink_arg_indices=[1],
        ),
        pure=False,
    ),
]


# =============================================================================
# TORCH NN FUNCTIONAL
# =============================================================================

TORCH_NN_FUNCTIONAL = [
    LibraryContract(
        module="torch.nn.functional",
        function="softmax",
        signature="(input, dim=None) -> Tensor",
        description="Apply softmax along dimension",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(min_value=0.0, max_value=1.0),
        preconditions=[
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        postconditions=[
            Postcondition("sum along dim equals 1", "value_constraint"),
            Postcondition("all values in [0, 1]", "value_constraint"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.nn.functional",
        function="log_softmax",
        signature="(input, dim=None) -> Tensor",
        description="Apply log softmax along dimension",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(max_value=0.0),  # log of [0,1] is <= 0
        preconditions=[
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.nn.functional",
        function="relu",
        signature="(input, inplace=False) -> Tensor",
        description="Apply ReLU activation",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(non_negative=True),
        postconditions=[
            Postcondition("all values >= 0", "value_constraint"),
        ],
        modifies_args=[0] if "inplace" else [],
        pure=True,  # Unless inplace
    ),
    
    LibraryContract(
        module="torch.nn.functional",
        function="sigmoid",
        signature="(input) -> Tensor",
        description="Apply sigmoid activation",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_shape=_shape_same_as("input"),
        bounds_info=BoundsSpec(min_value=0.0, max_value=1.0),
        postconditions=[
            Postcondition("all values in (0, 1)", "value_constraint"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.nn.functional",
        function="cross_entropy",
        signature="(input, target, weight=None, ignore_index=-100, reduction='mean') -> Tensor",
        description="Compute cross entropy loss",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),
        preconditions=[
            Precondition(
                "input.shape[0] == target.shape[0]",
                "VALUE_ERROR",
            ),
            Precondition(
                "target values are valid class indices",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.nn.functional",
        function="linear",
        signature="(input, weight, bias=None) -> Tensor",
        description="Apply linear transformation",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "input.shape[-1] == weight.shape[-1]",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
]


# =============================================================================
# TENSOR COMPARISON
# =============================================================================

TORCH_COMPARISON = [
    LibraryContract(
        module="torch.Tensor",
        function="__eq__",
        signature="(self, other) -> Tensor",
        description="Element-wise equality",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__ne__",
        signature="(self, other) -> Tensor",
        description="Element-wise inequality",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__lt__",
        signature="(self, other) -> Tensor",
        description="Element-wise less than",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__le__",
        signature="(self, other) -> Tensor",
        description="Element-wise less than or equal",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__gt__",
        signature="(self, other) -> Tensor",
        description="Element-wise greater than",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="__ge__",
        signature="(self, other) -> Tensor",
        description="Element-wise greater than or equal",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        pure=True,
    ),
]


# =============================================================================
# TENSOR PROPERTIES (as method contracts)
# =============================================================================

TORCH_PROPERTIES = [
    LibraryContract(
        module="torch.Tensor",
        function="size",
        signature="(self, dim=None) -> torch.Size | int",
        description="Get tensor size",
        return_type=TypeSpec(base_type="torch.Size", union_types=["int"]),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),
        preconditions=[
            Precondition(
                "dim is valid dimension if specified",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="numel",
        signature="(self) -> int",
        description="Get total number of elements",
        return_type=_type("int"),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),
        postconditions=[
            Postcondition("result >= 0", "value_constraint"),
            Postcondition("result == product(self.shape)", "value_constraint"),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch.Tensor",
        function="dim",
        signature="(self) -> int",
        description="Get number of dimensions",
        return_type=_type("int"),
        return_nullability=Nullability.NEVER,
        bounds_info=BoundsSpec(non_negative=True),
        postconditions=[
            Postcondition("result >= 0", "value_constraint"),
        ],
        pure=True,
    ),
]


# =============================================================================
# CONCATENATION AND STACKING
# =============================================================================

TORCH_CONCAT = [
    LibraryContract(
        module="torch",
        function="cat",
        signature="(tensors, dim=0) -> Tensor",
        description="Concatenate tensors along dimension",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "tensors is not empty",
                "VALUE_ERROR",
                arg_indices=[0],
            ),
            Precondition(
                "all tensors have compatible shapes",
                "VALUE_ERROR",
            ),
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="stack",
        signature="(tensors, dim=0) -> Tensor",
        description="Stack tensors along new dimension",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "tensors is not empty",
                "VALUE_ERROR",
            ),
            Precondition(
                "all tensors have same shape",
                "VALUE_ERROR",
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="split",
        signature="(tensor, split_size_or_sections, dim=0) -> tuple[Tensor, ...]",
        description="Split tensor into chunks",
        return_type=_type("tuple", "Tensor"),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[2],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="chunk",
        signature="(input, chunks, dim=0) -> tuple[Tensor, ...]",
        description="Split tensor into specified number of chunks",
        return_type=_type("tuple", "Tensor"),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "chunks > 0",
                "VALUE_ERROR",
                arg_indices=[1],
            ),
            Precondition(
                "dim is valid dimension",
                "BOUNDS",
                arg_indices=[2],
            ),
        ],
        pure=True,
    ),
]


# =============================================================================
# SIMILARITY AND DISTANCE FUNCTIONS - Key for Deferred Barrier Checking
# =============================================================================

TORCH_SIMILARITY = [
    # Cosine Similarity: Returns values in [-1, 1]
    # This is crucial for deferred barrier checking:
    # cosine_similarity(x, y) - 3 has interval [-4, -2], proving it can never be 0
    LibraryContract(
        module="torch.nn.functional",
        function="cosine_similarity",
        signature="(x1, x2, dim=1, eps=1e-8) -> Tensor",
        description="Cosine similarity between x1 and x2 along dim",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # KEY: Value bounds enable proving cosine_similarity(x,y) - 3 != 0
        return_interval=Interval.between(-1.0, 1.0),
        bounds_info=BoundsSpec(min_value=-1.0, max_value=1.0),
        postconditions=[
            Postcondition.cosine_range(),  # result ∈ [-1, 1]
        ],
        preconditions=[
            Precondition(
                "x1 and x2 have compatible shapes",
                "VALUE_ERROR",
                arg_indices=[0, 1],
            ),
        ],
        pure=True,
    ),
    
    LibraryContract(
        module="torch",
        function="cosine_similarity",
        signature="(x1, x2, dim=1, eps=1e-8) -> Tensor",
        description="Cosine similarity between x1 and x2 along dim",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.between(-1.0, 1.0),
        bounds_info=BoundsSpec(min_value=-1.0, max_value=1.0),
        postconditions=[
            Postcondition.cosine_range(),
        ],
        pure=True,
    ),
    
    # Pairwise Distance
    LibraryContract(
        module="torch.nn.functional",
        function="pairwise_distance",
        signature="(x1, x2, p=2.0, eps=1e-6, keepdim=False) -> Tensor",
        description="Pairwise distance between x1 and x2",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # Distances are always non-negative
        return_interval=Interval.non_negative(),
        bounds_info=BoundsSpec(min_value=0.0, non_negative=True),
        postconditions=[
            Postcondition.non_negative(),
        ],
        pure=True,
    ),
    
    # Sigmoid: Returns values in (0, 1)
    LibraryContract(
        module="torch",
        function="sigmoid",
        signature="(input) -> Tensor",
        description="Applies sigmoid element-wise",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.between(0.0, 1.0),
        bounds_info=BoundsSpec(min_value=0.0, max_value=1.0, non_negative=True),
        postconditions=[
            Postcondition.unit_interval(),
        ],
        pure=True,
    ),
    
    # Tanh: Returns values in (-1, 1)
    LibraryContract(
        module="torch",
        function="tanh",
        signature="(input) -> Tensor",
        description="Applies tanh element-wise",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.between(-1.0, 1.0),
        bounds_info=BoundsSpec(min_value=-1.0, max_value=1.0),
        postconditions=[
            Postcondition.value_in_range(-1.0, 1.0),
        ],
        pure=True,
    ),
    
    # Clamp: Returns values in [min, max]
    LibraryContract(
        module="torch",
        function="clamp",
        signature="(input, min=None, max=None) -> Tensor",
        description="Clamps all elements to [min, max]",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # Note: Actual interval depends on min/max args
        # This would need to be computed at analysis time
        return_shape=_shape_same_as("input"),
        pure=True,
    ),
    
    # Abs: Returns non-negative values
    LibraryContract(
        module="torch",
        function="abs",
        signature="(input) -> Tensor",
        description="Computes absolute value element-wise",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.non_negative(),
        bounds_info=BoundsSpec(min_value=0.0, non_negative=True),
        postconditions=[
            Postcondition.non_negative(),
        ],
        return_shape=_shape_same_as("input"),
        pure=True,
    ),
    
    # Exp: Returns positive values
    LibraryContract(
        module="torch",
        function="exp",
        signature="(input) -> Tensor",
        description="Computes exponential element-wise",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.positive(),
        bounds_info=BoundsSpec(min_value=0.0, non_negative=True, non_zero=True),
        postconditions=[
            Postcondition.non_zero(),  # exp(x) > 0 always
            Postcondition.non_negative(),
        ],
        return_shape=_shape_same_as("input"),
        pure=True,
    ),
    
    # Square: Returns non-negative values
    LibraryContract(
        module="torch",
        function="square",
        signature="(input) -> Tensor",
        description="Computes element-wise square",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.non_negative(),
        bounds_info=BoundsSpec(min_value=0.0, non_negative=True),
        postconditions=[
            Postcondition.non_negative(),
        ],
        return_shape=_shape_same_as("input"),
        pure=True,
    ),
    
    # Sqrt: Returns non-negative values (for non-negative input)
    LibraryContract(
        module="torch",
        function="sqrt",
        signature="(input) -> Tensor",
        description="Computes element-wise square root",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.non_negative(),
        bounds_info=BoundsSpec(min_value=0.0, non_negative=True),
        postconditions=[
            Postcondition.non_negative(),
        ],
        preconditions=[
            Precondition(
                "input >= 0 (for real output)",
                "VALUE_ERROR",
                arg_indices=[0],
            ),
        ],
        return_shape=_shape_same_as("input"),
        pure=True,
    ),
    
    # Log: Requires positive input
    LibraryContract(
        module="torch",
        function="log",
        signature="(input) -> Tensor",
        description="Computes natural logarithm element-wise",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        # Log can return any real value
        return_shape=_shape_same_as("input"),
        preconditions=[
            Precondition(
                "input > 0",
                "VALUE_ERROR",
                arg_indices=[0],
            ),
        ],
        pure=True,
    ),
    
    # Norm: Returns non-negative values
    LibraryContract(
        module="torch.linalg",
        function="norm",
        signature="(A, ord=None, dim=None, keepdim=False) -> Tensor",
        description="Computes matrix or vector norm",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        return_interval=Interval.non_negative(),
        bounds_info=BoundsSpec(min_value=0.0, non_negative=True),
        postconditions=[
            Postcondition.non_negative(),
        ],
        pure=True,
    ),
    
    # Dot product - can return any value
    LibraryContract(
        module="torch",
        function="dot",
        signature="(input, tensor) -> Tensor",
        description="Computes dot product of two 1D tensors",
        return_type=_tensor_type(),
        return_nullability=Nullability.NEVER,
        preconditions=[
            Precondition(
                "input.dim() == 1",
                "VALUE_ERROR",
                arg_indices=[0],
            ),
            Precondition(
                "tensor.dim() == 1",
                "VALUE_ERROR",
                arg_indices=[1],
            ),
            Precondition(
                "input.size(0) == tensor.size(0)",
                "VALUE_ERROR",
                arg_indices=[0, 1],
            ),
        ],
        pure=True,
    ),
]


# =============================================================================
# REGISTRATION
# =============================================================================

ALL_TORCH_CONTRACTS = (
    TORCH_TENSOR_CREATION +
    TORCH_TENSOR_INDEXING +
    TORCH_TENSOR_SHAPE +
    TORCH_TENSOR_REDUCTION +
    TORCH_TENSOR_ARITHMETIC +
    TORCH_TENSOR_NORM +
    TORCH_IO +
    TORCH_NN_FUNCTIONAL +
    TORCH_COMPARISON +
    TORCH_PROPERTIES +
    TORCH_CONCAT +
    TORCH_SIMILARITY
)


def register_torch_contracts() -> int:
    """Register all PyTorch contracts. Returns number registered."""
    for contract in ALL_TORCH_CONTRACTS:
        register_contract(contract)
    return len(ALL_TORCH_CONTRACTS)


def get_torch_contract(function_name: str) -> LibraryContract | None:
    """Get a torch contract by function name (e.g., 'torch.randn', 'Tensor.view')."""
    from .base import get_contract
    
    # Try with torch prefix
    if not function_name.startswith("torch"):
        result = get_contract(f"torch.{function_name}")
        if result:
            return result
        result = get_contract(f"torch.Tensor.{function_name}")
        if result:
            return result
    
    return get_contract(function_name)
