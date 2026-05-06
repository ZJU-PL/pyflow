"""
Contract-Aware Bug Checker

Integrates library contracts with the static analyzer to make precise
bug/not-bug determinations based on library semantics.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import (
    BoundsSpec,
    ContractRegistry,
    DimSource,
    LibraryContract,
    Nullability,
    ShapeSpec,
    TaintBehavior,
    get_global_registry,
)


@dataclass
class TensorShape:
    """Tracked shape of a tensor."""
    dims: list[int | str | None]  # None means unknown
    
    def __len__(self) -> int:
        return len(self.dims)
    
    @property
    def ndim(self) -> int:
        return len(self.dims)
    
    def get_dim(self, index: int) -> int | str | None:
        """Get dimension size, handling negative indices."""
        if -len(self.dims) <= index < len(self.dims):
            return self.dims[index]
        return None
    
    def is_valid_index(self, dim: int, index: int) -> bool | None:
        """Check if index is valid for dimension. Returns None if unknown."""
        size = self.get_dim(dim)
        if size is None or isinstance(size, str):
            return None  # Unknown
        if isinstance(index, int):
            return -size <= index < size
        return None  # Unknown index
    
    @classmethod
    def from_literal(cls, *dims: int) -> TensorShape:
        return cls(dims=list(dims))
    
    @classmethod
    def unknown(cls, ndim: int | None = None) -> TensorShape:
        if ndim is None:
            return cls(dims=[])
        return cls(dims=[None] * ndim)


@dataclass
class ValueBounds:
    """Tracked bounds on a value."""
    min_value: float | None = None
    max_value: float | None = None
    non_negative: bool = False
    non_zero: bool = False
    equals: float | None = None
    
    def contains(self, value: float) -> bool | None:
        """Check if value is within bounds. Returns None if unknown."""
        if self.equals is not None:
            return value == self.equals
        
        result = True
        if self.min_value is not None and value < self.min_value:
            result = False
        if self.max_value is not None and value > self.max_value:
            result = False
        if self.non_negative and value < 0:
            result = False
        if self.non_zero and value == 0:
            result = False
        
        return result
    
    def could_be_zero(self) -> bool:
        """Check if zero is a possible value."""
        if self.equals is not None:
            return self.equals == 0
        if self.non_zero:
            return False
        if self.min_value is not None and self.min_value > 0:
            return False
        if self.max_value is not None and self.max_value < 0:
            return False
        return True
    
    @classmethod
    def from_spec(cls, spec: BoundsSpec) -> ValueBounds:
        """Create from a BoundsSpec."""
        min_val = spec.min_value if isinstance(spec.min_value, (int, float)) else None
        max_val = spec.max_value if isinstance(spec.max_value, (int, float)) else None
        return cls(
            min_value=min_val,
            max_value=max_val,
            non_negative=spec.non_negative,
            non_zero=spec.non_zero,
            equals=spec.equals_value,
        )


@dataclass
class ContractCheckResult:
    """Result of checking a contract."""
    is_bug: bool
    bug_type: str | None = None
    message: str | None = None
    confidence: float = 1.0
    precondition_violated: str | None = None
    contract: LibraryContract | None = None


@dataclass
class TrackedValue:
    """A value being tracked through analysis."""
    name: str
    shape: TensorShape | None = None
    bounds: ValueBounds | None = None
    nullability: Nullability = Nullability.SOMETIMES
    is_tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
    source_contract: LibraryContract | None = None


class ContractChecker:
    """
    Checks function calls against library contracts to detect bugs.
    """
    
    def __init__(self, registry: ContractRegistry | None = None):
        self.registry = registry or get_global_registry()
        self.tracked_values: dict[str, TrackedValue] = {}
    
    def track_value(
        self,
        name: str,
        shape: TensorShape | None = None,
        bounds: ValueBounds | None = None,
        nullability: Nullability = Nullability.SOMETIMES,
        contract: LibraryContract | None = None,
    ) -> TrackedValue:
        """Track a value with its properties."""
        value = TrackedValue(
            name=name,
            shape=shape,
            bounds=bounds,
            nullability=nullability,
            source_contract=contract,
        )
        self.tracked_values[name] = value
        return value
    
    def get_tracked(self, name: str) -> TrackedValue | None:
        """Get tracked value by name."""
        return self.tracked_values.get(name)
    
    def check_call(
        self,
        function_name: str,
        args: list[Any],
        kwargs: dict[str, Any] | None = None,
        result_name: str | None = None,
    ) -> ContractCheckResult:
        """
        Check a function call against its contract.
        
        Returns ContractCheckResult indicating if call is buggy.
        """
        kwargs = kwargs or {}
        
        # Look up contract
        contract = self._resolve_contract(function_name)
        if not contract:
            return ContractCheckResult(is_bug=False, message="No contract found")
        
        # Check preconditions
        for precond in contract.preconditions:
            violation = self._check_precondition(precond, args, kwargs)
            if violation:
                return ContractCheckResult(
                    is_bug=True,
                    bug_type=precond.violation_type,
                    message=f"Precondition violated: {precond.condition}",
                    precondition_violated=precond.condition,
                    contract=contract,
                    confidence=0.9 if precond.severity == "HIGH" else 0.7,
                )
        
        # Check taint sinks
        if contract.taint_spec.behavior == TaintBehavior.SINK:
            taint_result = self._check_taint_sink(contract, args)
            if taint_result.is_bug:
                return taint_result
        
        # If call is safe, track result
        if result_name:
            self._track_result(result_name, contract, args, kwargs)
        
        return ContractCheckResult(is_bug=False, contract=contract)
    
    def _resolve_contract(self, function_name: str) -> LibraryContract | None:
        """Resolve function name to contract."""
        # Direct lookup
        contract = self.registry.get(function_name)
        if contract:
            return contract
        
        # Try common patterns
        patterns = [
            function_name,
            f"torch.{function_name}",
            f"torch.Tensor.{function_name}",
            f"torch.nn.functional.{function_name}",
            f"numpy.{function_name}",
            f"numpy.ndarray.{function_name}",
        ]
        
        for pattern in patterns:
            contract = self.registry.get(pattern)
            if contract:
                return contract
        
        return None
    
    def _check_precondition(
        self,
        precond,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> bool:
        """
        Check if a precondition is violated.
        Returns True if VIOLATED (bug found).
        """
        bug_type = precond.violation_type
        
        # Check based on bug type
        if bug_type == "DIV_ZERO":
            return self._check_div_zero_precond(precond, args, kwargs)
        
        if bug_type == "NULL_PTR":
            return self._check_null_precond(precond, args, kwargs)
        
        if bug_type == "BOUNDS":
            return self._check_bounds_precond(precond, args, kwargs)
        
        if bug_type == "VALUE_ERROR":
            return self._check_value_error_precond(precond, args, kwargs)
        
        return False
    
    def _check_div_zero_precond(
        self,
        precond,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> bool:
        """Check division by zero precondition."""
        for arg_idx in precond.arg_indices:
            if arg_idx >= len(args):
                continue
            arg = args[arg_idx]
            
            # Check literal zero
            if arg == 0:
                return True
            
            # Check tracked value bounds
            if isinstance(arg, str) and arg in self.tracked_values:
                tracked = self.tracked_values[arg]
                if tracked.bounds:
                    # Known to be exactly zero
                    if tracked.bounds.equals == 0:
                        return True
                    # Known to be non-zero - not a violation
                    if tracked.bounds.non_zero:
                        return False
        
        return False
    
    def _check_null_precond(
        self,
        precond,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> bool:
        """Check null pointer precondition."""
        for arg_idx in precond.arg_indices:
            if arg_idx >= len(args):
                continue
            arg = args[arg_idx]
            
            # Check literal None
            if arg is None:
                return True
            
            # Check tracked value nullability
            if isinstance(arg, str) and arg in self.tracked_values:
                tracked = self.tracked_values[arg]
                if tracked.nullability == Nullability.ALWAYS:
                    return True
        
        return False
    
    def _check_bounds_precond(
        self,
        precond,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> bool:
        """Check bounds precondition (index out of range)."""
        # This requires shape information
        # For now, return False (no violation detected)
        # Real implementation would check index against tracked shapes
        return False
    
    def _check_value_error_precond(
        self,
        precond,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> bool:
        """Check value error preconditions (shape mismatch, etc.)."""
        # Requires semantic understanding of the specific precondition
        return False
    
    def _check_taint_sink(
        self,
        contract: LibraryContract,
        args: list[Any],
    ) -> ContractCheckResult:
        """Check if tainted data reaches a sink."""
        sink_indices = contract.taint_spec.sink_arg_indices or range(len(args))
        
        for idx in sink_indices:
            if idx >= len(args):
                continue
            arg = args[idx]
            
            # Check if argument is tainted
            if isinstance(arg, str) and arg in self.tracked_values:
                tracked = self.tracked_values[arg]
                if tracked.is_tainted:
                    return ContractCheckResult(
                        is_bug=True,
                        bug_type=contract.taint_spec.sink_type,
                        message=f"Tainted data reaches sink: {contract.function}",
                        contract=contract,
                        confidence=0.95,
                    )
        
        return ContractCheckResult(is_bug=False)
    
    def _track_result(
        self,
        result_name: str,
        contract: LibraryContract,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> None:
        """Track the result of a function call based on its contract."""
        # Determine shape
        shape = None
        if contract.return_shape:
            shape = self._compute_result_shape(contract.return_shape, args, kwargs)
        
        # Determine bounds
        bounds = None
        if contract.bounds_info:
            bounds = ValueBounds.from_spec(contract.bounds_info)
        
        # Determine nullability
        nullability = contract.return_nullability
        
        # Track the result
        self.track_value(
            result_name,
            shape=shape,
            bounds=bounds,
            nullability=nullability,
            contract=contract,
        )
        
        # Propagate taint if applicable
        if contract.taint_spec.behavior == TaintBehavior.PROPAGATE:
            self._propagate_taint(result_name, contract, args)
    
    def _compute_result_shape(
        self,
        shape_spec: ShapeSpec,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> TensorShape | None:
        """Compute result shape from shape spec and arguments."""
        if shape_spec.same_as:
            # Shape is same as an input
            arg_name = shape_spec.same_as
            if arg_name in self.tracked_values:
                tracked = self.tracked_values[arg_name]
                return tracked.shape
            return None
        
        if not shape_spec.dims:
            return None
        
        result_dims: list[int | str | None] = []
        for dim_spec in shape_spec.dims:
            if dim_spec.source == DimSource.LITERAL:
                result_dims.append(dim_spec.value if isinstance(dim_spec.value, int) else None)
            elif dim_spec.source == DimSource.ARG:
                # Try to resolve from args
                # This is simplified - real implementation would parse the reference
                result_dims.append(None)  # Unknown
            else:
                result_dims.append(None)
        
        return TensorShape(dims=result_dims)
    
    def _propagate_taint(
        self,
        result_name: str,
        contract: LibraryContract,
        args: list[Any],
    ) -> None:
        """Propagate taint from inputs to output."""
        if result_name not in self.tracked_values:
            return
        
        result = self.tracked_values[result_name]
        taint_sources = contract.taint_spec.taint_sources or range(len(args))
        
        for idx in taint_sources:
            if idx >= len(args):
                continue
            arg = args[idx]
            
            if isinstance(arg, str) and arg in self.tracked_values:
                tracked = self.tracked_values[arg]
                if tracked.is_tainted:
                    result.is_tainted = True
                    result.taint_sources.extend(tracked.taint_sources)
    
    # =========================================================================
    # Tensor-specific helpers
    # =========================================================================
    
    def track_tensor(
        self,
        name: str,
        shape: tuple[int, ...] | list[int],
    ) -> TrackedValue:
        """Convenience method to track a tensor with known shape."""
        return self.track_value(
            name,
            shape=TensorShape.from_literal(*shape),
            nullability=Nullability.NEVER,
        )
    
    def check_tensor_index(
        self,
        tensor_name: str,
        dim: int,
        index: int | str,
    ) -> ContractCheckResult:
        """Check if an index is valid for a tensor dimension."""
        tracked = self.get_tracked(tensor_name)
        if not tracked or not tracked.shape:
            return ContractCheckResult(is_bug=False, message="Shape unknown")
        
        if isinstance(index, str):
            # Index is a variable - check if we track it
            index_tracked = self.get_tracked(index)
            if not index_tracked or not index_tracked.bounds:
                return ContractCheckResult(is_bug=False, message="Index unknown")
            # Would need to compare bounds to shape
            return ContractCheckResult(is_bug=False)
        
        # Index is literal
        is_valid = tracked.shape.is_valid_index(dim, index)
        if is_valid is None:
            return ContractCheckResult(is_bug=False, message="Validity unknown")
        
        if not is_valid:
            dim_size = tracked.shape.get_dim(dim)
            return ContractCheckResult(
                is_bug=True,
                bug_type="BOUNDS",
                message=f"Index {index} out of bounds for dimension {dim} (size {dim_size})",
                confidence=1.0,
            )
        
        return ContractCheckResult(is_bug=False)
    
    def check_division(
        self,
        numerator: str | float,
        denominator: str | float,
    ) -> ContractCheckResult:
        """Check if a division could cause divide by zero."""
        # Check literal zero
        if denominator == 0:
            return ContractCheckResult(
                is_bug=True,
                bug_type="DIV_ZERO",
                message="Division by literal zero",
                confidence=1.0,
            )
        
        # Check tracked value
        if isinstance(denominator, str):
            tracked = self.get_tracked(denominator)
            if tracked and tracked.bounds:
                if tracked.bounds.equals == 0:
                    return ContractCheckResult(
                        is_bug=True,
                        bug_type="DIV_ZERO",
                        message=f"Division by {denominator} which is known to be zero",
                        confidence=1.0,
                    )
                if tracked.bounds.non_zero:
                    return ContractCheckResult(
                        is_bug=False,
                        message=f"{denominator} is known to be non-zero",
                    )
                if not tracked.bounds.could_be_zero():
                    return ContractCheckResult(
                        is_bug=False,
                        message=f"{denominator} bounds exclude zero",
                    )
        
        return ContractCheckResult(
            is_bug=False,
            message="Cannot determine if division is safe",
        )


# =============================================================================
# AST-based contract checking
# =============================================================================

class ASTContractChecker(ast.NodeVisitor):
    """
    Walk AST and check function calls against contracts.
    """
    
    def __init__(self, checker: ContractChecker):
        self.checker = checker
        self.bugs: list[ContractCheckResult] = []
        self.current_file: str = ""
    
    def check_file(self, file_path: str | Path, source: str | None = None) -> list[ContractCheckResult]:
        """Check a Python file against contracts."""
        self.current_file = str(file_path)
        self.bugs = []
        
        if source is None:
            with open(file_path, "r") as f:
                source = f.read()
        
        try:
            tree = ast.parse(source)
            self.visit(tree)
        except SyntaxError:
            pass
        
        return self.bugs
    
    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls."""
        func_name = self._get_call_name(node)
        if not func_name:
            self.generic_visit(node)
            return
        
        # Look for tensor creation with literal shapes
        if func_name in ("torch.randn", "torch.zeros", "torch.ones", "torch.rand", "torch.empty"):
            self._check_tensor_creation(node, func_name)
        
        # Look for divisions
        if func_name in ("torch.div", "torch.Tensor.div"):
            self._check_division_call(node, func_name)
        
        # Look for torch.load with user input
        if func_name == "torch.load":
            self._check_torch_load(node)
        
        self.generic_visit(node)
    
    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Check subscript operations."""
        # Would check against tracked tensor shapes
        self.generic_visit(node)
    
    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check binary operations for division by zero."""
        if isinstance(node.op, (ast.Div, ast.FloorDiv)):
            self._check_division_binop(node)
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> str | None:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None
    
    def _check_tensor_creation(self, node: ast.Call, func_name: str) -> None:
        """Check tensor creation calls."""
        # Extract shape from literal arguments
        shape = []
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                if arg.value < 0:
                    # Negative dimension - bug
                    self.bugs.append(ContractCheckResult(
                        is_bug=True,
                        bug_type="VALUE_ERROR",
                        message=f"Negative dimension {arg.value} in {func_name}",
                        confidence=1.0,
                    ))
                shape.append(arg.value)
        
        # Track the result if assigned
        # (would need to track assignment target)
    
    def _check_division_call(self, node: ast.Call, func_name: str) -> None:
        """Check torch.div calls."""
        if len(node.args) < 2:
            return
        
        divisor = node.args[1]
        if isinstance(divisor, ast.Constant) and divisor.value == 0:
            self.bugs.append(ContractCheckResult(
                is_bug=True,
                bug_type="DIV_ZERO",
                message="Division by zero in torch.div call",
                confidence=1.0,
            ))
    
    def _check_division_binop(self, node: ast.BinOp) -> None:
        """Check division binary operations."""
        if isinstance(node.right, ast.Constant) and node.right.value == 0:
            self.bugs.append(ContractCheckResult(
                is_bug=True,
                bug_type="DIV_ZERO",
                message="Division by literal zero",
                confidence=1.0,
            ))
    
    def _check_torch_load(self, node: ast.Call) -> None:
        """Check torch.load for unsafe deserialization."""
        # Check if weights_only=True is set
        weights_only = False
        for keyword in node.keywords:
            if keyword.arg == "weights_only":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    weights_only = True
        
        if not weights_only:
            self.bugs.append(ContractCheckResult(
                is_bug=True,
                bug_type="UNSAFE_DESERIALIZATION",
                message="torch.load without weights_only=True allows arbitrary code execution",
                confidence=0.8,
            ))
