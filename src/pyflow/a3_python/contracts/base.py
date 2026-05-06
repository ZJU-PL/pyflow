"""
Library Contracts for Static Analysis - Barrier Theory Implementation

This module provides semantic specifications for external library functions
that enable precise bug/not-bug determinations during static analysis.

Implements Barrier Theory where:
- Contracts define semantic barriers at function boundaries
- Abstract values (shapes, bounds, nullability) propagate through barriers
- Deferred constraints enable proving safety from accumulated knowledge
  (e.g., cosine_similarity returns [-1,1], so cosine_similarity(x,y) - 3 ≠ 0)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Union
import math


# =============================================================================
# CORE ENUMERATIONS
# =============================================================================

class Nullability(Enum):
    """Whether a function can return None."""
    NEVER = auto()      # Always returns non-None
    SOMETIMES = auto()  # May return None under some conditions
    ALWAYS = auto()     # Always returns None (void functions)
    CONDITIONAL = auto()  # Depends on arguments


class DimSource(Enum):
    """Where a dimension value comes from."""
    LITERAL = auto()     # Literal integer value
    ARG = auto()         # From function argument
    ARG_SHAPE = auto()   # From shape of an argument tensor
    ATTR = auto()        # From object attribute
    COMPUTED = auto()    # Computed from expression
    SAME_AS_INPUT = auto()  # Same as input dimension
    UNKNOWN = auto()     # Cannot be determined statically


class TaintBehavior(Enum):
    """How a function handles tainted data."""
    PROPAGATE = auto()   # Taint flows from inputs to output
    SANITIZE = auto()    # Function sanitizes taint
    SINK = auto()        # Function is dangerous with tainted input
    NEUTRAL = auto()     # No taint relevance


class BarrierStrength(Enum):
    """
    How certain we are about a barrier's constraints.
    
    Higher strength = more confidence in bug/not-bug determination.
    """
    PROVEN = auto()      # Statically verified with certainty (1.0)
    STRONG = auto()      # Contract guarantees with tracked args (0.9)
    CONDITIONAL = auto() # Depends on runtime values (0.7)
    WEAK = auto()        # Heuristic/pattern-based (0.4)
    NONE = auto()        # No information available (0.0)
    
    def to_confidence(self) -> float:
        """Convert to numeric confidence score."""
        return {
            BarrierStrength.PROVEN: 1.0,
            BarrierStrength.STRONG: 0.9,
            BarrierStrength.CONDITIONAL: 0.7,
            BarrierStrength.WEAK: 0.4,
            BarrierStrength.NONE: 0.0,
        }[self]


class BarrierResult(Enum):
    """Result of checking a barrier."""
    DEFINITELY_SAFE = auto()    # Barrier definitely satisfied
    DEFINITELY_VIOLATED = auto() # Barrier definitely violated (BUG)
    MAYBE_VIOLATED = auto()     # Barrier might be violated (WARNING)
    UNKNOWN = auto()            # Cannot determine


# =============================================================================
# ABSTRACT VALUE DOMAIN - For Deferred Constraint Propagation
# =============================================================================

@dataclass
class Interval:
    """
    Interval abstract domain for numeric values.
    
    Enables deferred barrier checking:
    - cosine_similarity returns Interval(-1, 1)
    - cosine_similarity(x,y) - 3 returns Interval(-4, -2)
    - Division barrier check: 0 ∈ Interval(-4, -2)? NO → SAFE
    """
    min_val: float | None = None  # None = -∞
    max_val: float | None = None  # None = +∞
    
    # Discrete constraints
    excludes_zero: bool = False   # Guaranteed non-zero
    is_integer: bool = False      # Integer values only
    is_positive: bool = False     # Strictly > 0
    is_non_negative: bool = False # >= 0
    
    # Exact value (if known)
    exact_value: float | None = None
    
    def __post_init__(self):
        """Derive constraints from bounds."""
        if self.exact_value is not None:
            self.min_val = self.exact_value
            self.max_val = self.exact_value
            if self.exact_value != 0:
                self.excludes_zero = True
            if self.exact_value > 0:
                self.is_positive = True
            if self.exact_value >= 0:
                self.is_non_negative = True
        
        # Derive from bounds
        if self.min_val is not None and self.min_val > 0:
            self.is_positive = True
            self.is_non_negative = True
            self.excludes_zero = True
        elif self.min_val is not None and self.min_val >= 0:
            self.is_non_negative = True
        
        if self.max_val is not None and self.max_val < 0:
            self.excludes_zero = True
        
        # If both bounds are same sign, excludes zero
        if (self.min_val is not None and self.max_val is not None and 
            self.min_val > 0 and self.max_val > 0):
            self.excludes_zero = True
        if (self.min_val is not None and self.max_val is not None and 
            self.min_val < 0 and self.max_val < 0):
            self.excludes_zero = True
    
    def contains(self, value: float) -> bool:
        """Check if value is in interval."""
        if self.exact_value is not None:
            return value == self.exact_value
        if self.min_val is not None and value < self.min_val:
            return False
        if self.max_val is not None and value > self.max_val:
            return False
        if self.excludes_zero and value == 0:
            return False
        return True
    
    def contains_zero(self) -> bool:
        """Check if zero could be in this interval."""
        if self.excludes_zero:
            return False
        if self.exact_value is not None:
            return self.exact_value == 0
        if self.min_val is not None and self.min_val > 0:
            return False
        if self.max_val is not None and self.max_val < 0:
            return False
        return True
    
    def is_definitely_zero(self) -> bool:
        """Check if value is definitely zero."""
        return self.exact_value == 0
    
    def is_definitely_non_zero(self) -> bool:
        """Check if value is definitely non-zero."""
        return self.excludes_zero
    
    @classmethod
    def exactly(cls, value: float) -> Interval:
        """Create interval for exact value."""
        return cls(exact_value=value)
    
    @classmethod
    def between(cls, min_val: float, max_val: float) -> Interval:
        """Create bounded interval."""
        return cls(min_val=min_val, max_val=max_val)
    
    @classmethod
    def at_least(cls, min_val: float) -> Interval:
        """Create interval [min_val, +∞)."""
        return cls(min_val=min_val)
    
    @classmethod
    def at_most(cls, max_val: float) -> Interval:
        """Create interval (-∞, max_val]."""
        return cls(max_val=max_val)
    
    @classmethod
    def non_negative(cls) -> Interval:
        """Create interval [0, +∞)."""
        return cls(min_val=0, is_non_negative=True)
    
    @classmethod
    def positive(cls) -> Interval:
        """Create interval (0, +∞)."""
        return cls(min_val=0, is_positive=True, excludes_zero=True)
    
    @classmethod
    def non_zero(cls) -> Interval:
        """Create interval excluding zero."""
        return cls(excludes_zero=True)
    
    @classmethod
    def unknown(cls) -> Interval:
        """Create unbounded interval (-∞, +∞)."""
        return cls()
    
    @classmethod
    def unit_interval(cls) -> Interval:
        """Create [0, 1] interval."""
        return cls(min_val=0, max_val=1, is_non_negative=True)
    
    @classmethod
    def cosine_similarity_range(cls) -> Interval:
        """Create [-1, 1] interval for cosine similarity."""
        return cls(min_val=-1, max_val=1)
    
    @classmethod
    def probability(cls) -> Interval:
        """Create [0, 1] interval for probabilities."""
        return cls(min_val=0, max_val=1, is_non_negative=True)
    
    # =========================================================================
    # Arithmetic Propagation - Key for deferred barrier checking
    # =========================================================================
    
    def __add__(self, other: Interval | float) -> Interval:
        """Interval addition: [a,b] + [c,d] = [a+c, b+d]."""
        if isinstance(other, (int, float)):
            other = Interval.exactly(other)
        
        new_min = None
        new_max = None
        
        if self.min_val is not None and other.min_val is not None:
            new_min = self.min_val + other.min_val
        if self.max_val is not None and other.max_val is not None:
            new_max = self.max_val + other.max_val
        
        return Interval(min_val=new_min, max_val=new_max)
    
    def __radd__(self, other: float) -> Interval:
        return self.__add__(other)
    
    def __sub__(self, other: Interval | float) -> Interval:
        """Interval subtraction: [a,b] - [c,d] = [a-d, b-c]."""
        if isinstance(other, (int, float)):
            other = Interval.exactly(other)
        
        new_min = None
        new_max = None
        
        if self.min_val is not None and other.max_val is not None:
            new_min = self.min_val - other.max_val
        if self.max_val is not None and other.min_val is not None:
            new_max = self.max_val - other.min_val
        
        return Interval(min_val=new_min, max_val=new_max)
    
    def __rsub__(self, other: float) -> Interval:
        """other - self."""
        return Interval.exactly(other).__sub__(self)
    
    def __mul__(self, other: Interval | float) -> Interval:
        """Interval multiplication."""
        if isinstance(other, (int, float)):
            other = Interval.exactly(other)
        
        # Handle exact values
        if self.exact_value is not None and other.exact_value is not None:
            return Interval.exactly(self.exact_value * other.exact_value)
        
        # General case: compute all corner products
        corners = []
        for a in [self.min_val, self.max_val]:
            for b in [other.min_val, other.max_val]:
                if a is not None and b is not None:
                    corners.append(a * b)
        
        if not corners:
            return Interval.unknown()
        
        return Interval(min_val=min(corners), max_val=max(corners))
    
    def __rmul__(self, other: float) -> Interval:
        return self.__mul__(other)
    
    def __truediv__(self, other: Interval | float) -> Interval:
        """Interval division (assumes divisor doesn't contain zero)."""
        if isinstance(other, (int, float)):
            other = Interval.exactly(other)
        
        # Check for division by zero
        if other.contains_zero():
            # Conservatively return unknown
            return Interval.unknown()
        
        if other.exact_value is not None:
            if self.exact_value is not None:
                return Interval.exactly(self.exact_value / other.exact_value)
            new_min = self.min_val / other.exact_value if self.min_val is not None else None
            new_max = self.max_val / other.exact_value if self.max_val is not None else None
            if other.exact_value < 0:
                new_min, new_max = new_max, new_min
            return Interval(min_val=new_min, max_val=new_max)
        
        return Interval.unknown()
    
    def __neg__(self) -> Interval:
        """Negation: -[a,b] = [-b, -a]."""
        new_min = -self.max_val if self.max_val is not None else None
        new_max = -self.min_val if self.min_val is not None else None
        return Interval(min_val=new_min, max_val=new_max)
    
    def __abs__(self) -> Interval:
        """Absolute value."""
        if self.min_val is not None and self.min_val >= 0:
            return self
        if self.max_val is not None and self.max_val <= 0:
            return -self
        
        # Interval spans zero
        new_max = max(
            abs(self.min_val) if self.min_val is not None else float('inf'),
            abs(self.max_val) if self.max_val is not None else float('inf')
        )
        return Interval(min_val=0, max_val=new_max if new_max != float('inf') else None)
    
    def sqrt(self) -> Interval:
        """Square root (domain: non-negative reals)."""
        if self.max_val is not None and self.max_val < 0:
            return Interval.unknown()  # Invalid input
        
        new_min = math.sqrt(max(0, self.min_val)) if self.min_val is not None else 0
        new_max = math.sqrt(self.max_val) if self.max_val is not None else None
        return Interval(min_val=new_min, max_val=new_max, is_non_negative=True)
    
    def join(self, other: Interval) -> Interval:
        """Join (union) of two intervals - conservative over-approximation."""
        new_min = min(self.min_val, other.min_val) if self.min_val is not None and other.min_val is not None else None
        new_max = max(self.max_val, other.max_val) if self.max_val is not None and other.max_val is not None else None
        
        return Interval(
            min_val=new_min,
            max_val=new_max,
            excludes_zero=self.excludes_zero and other.excludes_zero,
            is_positive=self.is_positive and other.is_positive,
            is_non_negative=self.is_non_negative and other.is_non_negative,
        )
    
    def meet(self, other: Interval) -> Interval:
        """Meet (intersection) of two intervals."""
        new_min = max(self.min_val or float('-inf'), other.min_val or float('-inf'))
        new_max = min(self.max_val or float('inf'), other.max_val or float('inf'))
        
        if new_min > new_max:
            # Empty intersection - return bottom
            return Interval.exactly(float('nan'))
        
        return Interval(
            min_val=new_min if new_min != float('-inf') else None,
            max_val=new_max if new_max != float('inf') else None,
            excludes_zero=self.excludes_zero or other.excludes_zero,
        )
    
    def __repr__(self) -> str:
        if self.exact_value is not None:
            return f"Interval({self.exact_value})"
        
        left = f"[{self.min_val}" if self.min_val is not None else "(-∞"
        right = f"{self.max_val}]" if self.max_val is not None else "+∞)"
        
        extras = []
        if self.excludes_zero:
            extras.append("≠0")
        if self.is_positive:
            extras.append(">0")
        elif self.is_non_negative:
            extras.append("≥0")
        
        extra_str = f" {{{', '.join(extras)}}}" if extras else ""
        return f"Interval{left}, {right}{extra_str}"


@dataclass
class AbstractValue:
    """
    Complete abstract value tracking for barrier analysis.
    
    Tracks all properties that might be useful for deferred barrier checking:
    - Value bounds (interval)
    - Shape (for tensors)
    - Nullability
    - Taint
    - Origin (what contract produced this value)
    """
    name: str
    
    # Numeric interval for value bounds
    interval: Interval = field(default_factory=Interval.unknown)
    
    # Shape for tensors/arrays
    shape: list[int | str | None] | None = None
    
    # Nullability
    nullability: Nullability = Nullability.SOMETIMES
    
    # Taint tracking
    is_tainted: bool = False
    taint_types: set[str] = field(default_factory=set)
    
    # Origin tracking (for error messages)
    source_contract: str | None = None
    source_location: str | None = None
    
    # Barrier strength of this value
    barrier_strength: BarrierStrength = BarrierStrength.NONE
    
    def with_interval(self, interval: Interval) -> AbstractValue:
        """Return copy with updated interval."""
        return AbstractValue(
            name=self.name,
            interval=interval,
            shape=self.shape,
            nullability=self.nullability,
            is_tainted=self.is_tainted,
            taint_types=self.taint_types.copy(),
            source_contract=self.source_contract,
            source_location=self.source_location,
            barrier_strength=self.barrier_strength,
        )
    
    def can_be_zero(self) -> bool:
        """Check if this value could be zero (for division barrier)."""
        return self.interval.contains_zero()
    
    def is_definitely_non_zero(self) -> bool:
        """Check if value is definitely non-zero."""
        return self.interval.is_definitely_non_zero()
    
    def is_definitely_non_null(self) -> bool:
        """Check if value is definitely not None."""
        return self.nullability == Nullability.NEVER
    
    def get_shape_dim(self, dim: int) -> int | None:
        """Get size of dimension (None if unknown)."""
        if self.shape is None:
            return None
        if dim < 0:
            dim = len(self.shape) + dim
        if 0 <= dim < len(self.shape):
            val = self.shape[dim]
            return val if isinstance(val, int) else None
        return None


# =============================================================================
# BARRIER DEFINITIONS
# =============================================================================

@dataclass
class Barrier:
    """
    A semantic barrier representing a constraint that must be satisfied.
    
    Barriers are established by contracts and checked during analysis.
    Deferred barriers can be checked later once more information is available.
    """
    barrier_type: str  # "DIV_ZERO", "BOUNDS", "NULL_PTR", "TAINT_SINK", etc.
    condition: str     # Human-readable condition
    
    # The abstract value(s) involved
    subject_name: str
    
    # What must be true for the barrier to be satisfied
    required_interval: Interval | None = None  # e.g., must not contain 0
    required_nullability: Nullability | None = None
    required_shape_constraint: str | None = None
    
    # Barrier strength
    strength: BarrierStrength = BarrierStrength.STRONG
    
    # Location for error reporting
    location: str | None = None
    
    def check(self, value: AbstractValue) -> BarrierResult:
        """
        Check if the barrier is satisfied by the given abstract value.
        
        This is where deferred constraint checking happens:
        e.g., cosine_similarity(x,y) - 3 with interval [-4, -2]
              → check if 0 ∈ [-4, -2] → NO → DEFINITELY_SAFE
        """
        if self.barrier_type == "DIV_ZERO":
            if value.is_definitely_non_zero():
                return BarrierResult.DEFINITELY_SAFE
            elif value.interval.is_definitely_zero():
                return BarrierResult.DEFINITELY_VIOLATED
            elif value.can_be_zero():
                return BarrierResult.MAYBE_VIOLATED
            else:
                return BarrierResult.UNKNOWN
        
        elif self.barrier_type == "NULL_PTR":
            if value.nullability == Nullability.NEVER:
                return BarrierResult.DEFINITELY_SAFE
            elif value.nullability == Nullability.ALWAYS:
                return BarrierResult.DEFINITELY_VIOLATED
            else:
                return BarrierResult.MAYBE_VIOLATED
        
        elif self.barrier_type == "BOUNDS":
            if self.required_interval is not None:
                # Check if value interval is within bounds
                if (value.interval.max_val is not None and 
                    self.required_interval.max_val is not None and
                    value.interval.max_val < self.required_interval.max_val):
                    return BarrierResult.DEFINITELY_SAFE
                elif (value.interval.min_val is not None and
                      self.required_interval.max_val is not None and
                      value.interval.min_val >= self.required_interval.max_val):
                    return BarrierResult.DEFINITELY_VIOLATED
            return BarrierResult.MAYBE_VIOLATED
        
        elif self.barrier_type == "TAINT_SINK":
            if not value.is_tainted:
                return BarrierResult.DEFINITELY_SAFE
            else:
                return BarrierResult.DEFINITELY_VIOLATED
        
        return BarrierResult.UNKNOWN
    
    def to_bug_type(self) -> str:
        """Convert barrier type to bug type for reporting."""
        return self.barrier_type


@dataclass
class DeferredBarrier:
    """
    A barrier check that is deferred until more information is available.
    
    Example: 
        x = cosine_similarity(a, b)  # x.interval = [-1, 1]
        y = x - 3                    # y.interval = [-4, -2]
        z = 1 / y                    # Barrier: y ≠ 0
        
    The barrier at z can be resolved because we've tracked that y ∈ [-4, -2].
    """
    barrier: Barrier
    subject: AbstractValue
    expression_chain: list[str] = field(default_factory=list)
    
    def try_resolve(self) -> BarrierResult:
        """Attempt to resolve the deferred barrier with current knowledge."""
        return self.barrier.check(self.subject)


# =============================================================================
# DIMENSION AND SHAPE SPECIFICATIONS
# =============================================================================

@dataclass
class DimSpec:
    """Specification for a single dimension of a tensor/array."""
    source: DimSource
    value: int | str | None = None  # Literal value or reference
    expr: str | None = None         # Expression for COMPUTED
    min_value: int | None = None
    max_value: int | None = None
    
    @classmethod
    def literal(cls, value: int) -> DimSpec:
        """Create a dimension with a literal value."""
        return cls(source=DimSource.LITERAL, value=value, min_value=value, max_value=value)
    
    @classmethod
    def from_arg(cls, arg_name: str, index: int | None = None) -> DimSpec:
        """Create a dimension from a function argument."""
        ref = f"{arg_name}[{index}]" if index is not None else arg_name
        return cls(source=DimSource.ARG, value=ref)
    
    @classmethod
    def from_input_shape(cls, arg_name: str, dim: int) -> DimSpec:
        """Create a dimension from input tensor's shape."""
        return cls(source=DimSource.ARG_SHAPE, value=f"{arg_name}.shape[{dim}]")
    
    @classmethod
    def computed(cls, expr: str, min_val: int | None = None, max_val: int | None = None) -> DimSpec:
        """Create a computed dimension."""
        return cls(source=DimSource.COMPUTED, expr=expr, min_value=min_val, max_value=max_val)
    
    @classmethod
    def same_as(cls, arg_name: str, dim: int) -> DimSpec:
        """Dimension is same as input's dimension."""
        return cls(source=DimSource.SAME_AS_INPUT, value=f"{arg_name}[{dim}]")
    
    @classmethod
    def unknown(cls) -> DimSpec:
        """Dimension cannot be determined statically."""
        return cls(source=DimSource.UNKNOWN)


@dataclass
class ShapeSpec:
    """Specification for tensor/array shapes."""
    dims: list[DimSpec] = field(default_factory=list)
    ndim_min: int | None = None  # Minimum number of dimensions
    ndim_max: int | None = None  # Maximum number of dimensions
    same_as: str | None = None   # Shape is same as this argument
    
    @classmethod
    def from_args(cls, *size_args: str) -> ShapeSpec:
        """Shape comes from size arguments (e.g., torch.zeros(3, 4, 5))."""
        return cls(dims=[DimSpec.from_arg("size", i) for i in range(len(size_args))])
    
    @classmethod
    def same_as_input(cls, arg_name: str) -> ShapeSpec:
        """Shape is identical to an input tensor."""
        return cls(same_as=arg_name)
    
    @classmethod
    def unknown(cls, ndim_min: int | None = None, ndim_max: int | None = None) -> ShapeSpec:
        """Unknown shape with optional dimensionality constraints."""
        return cls(ndim_min=ndim_min, ndim_max=ndim_max)


@dataclass
class BoundsSpec:
    """Bounds information for values and indices."""
    # For indexable dimensions: dim -> (min, max) valid indices
    indexable_dims: dict[int, tuple[int | str | None, int | str | None]] = field(default_factory=dict)
    
    # Value constraints as Interval
    value_interval: Interval = field(default_factory=Interval.unknown)
    
    # Legacy compatibility
    min_value: float | str | None = None
    max_value: float | str | None = None
    
    # Special constraints
    non_negative: bool = False
    non_zero: bool = False
    finite: bool = True
    integer_only: bool = False
    
    # Specific value (e.g., zeros tensor)
    equals_value: float | None = None
    
    def __post_init__(self):
        """Convert legacy bounds to Interval."""
        if self.equals_value is not None:
            self.value_interval = Interval.exactly(self.equals_value)
        elif self.min_value is not None or self.max_value is not None:
            min_v = self.min_value if isinstance(self.min_value, (int, float)) else None
            max_v = self.max_value if isinstance(self.max_value, (int, float)) else None
            self.value_interval = Interval(
                min_val=min_v,
                max_val=max_v,
                excludes_zero=self.non_zero,
                is_non_negative=self.non_negative,
            )
        elif self.non_zero:
            self.value_interval = Interval.non_zero()
        elif self.non_negative:
            self.value_interval = Interval.non_negative()
    
    def get_interval(self) -> Interval:
        """Get the value interval."""
        return self.value_interval


# =============================================================================
# PRECONDITIONS AND POSTCONDITIONS
# =============================================================================

@dataclass
class Precondition:
    """A condition that must hold before function invocation - establishes a barrier."""
    condition: str                    # Human-readable description
    violation_type: str               # Bug type if violated (e.g., "BOUNDS", "DIV_ZERO")
    arg_indices: list[int] = field(default_factory=list)  # Which args are involved
    check_expr: str | None = None     # Optional expression to check
    severity: str = "HIGH"            # HIGH, MEDIUM, LOW
    
    # Barrier that this precondition establishes
    required_interval: Interval | None = None
    
    @classmethod
    def non_zero_arg(cls, arg_index: int, arg_name: str = "divisor") -> Precondition:
        """Argument must be non-zero (for division)."""
        return cls(
            condition=f"{arg_name} != 0",
            violation_type="DIV_ZERO",
            arg_indices=[arg_index],
            check_expr=f"arg_{arg_index} != 0",
            required_interval=Interval.non_zero(),
        )
    
    @classmethod
    def non_null_arg(cls, arg_index: int, arg_name: str = "input") -> Precondition:
        """Argument must not be None."""
        return cls(
            condition=f"{arg_name} is not None",
            violation_type="NULL_PTR",
            arg_indices=[arg_index],
            check_expr=f"arg_{arg_index} is not None"
        )
    
    @classmethod
    def valid_index(cls, index_arg: int, size_ref: str) -> Precondition:
        """Index must be within valid range."""
        return cls(
            condition=f"0 <= index < {size_ref}",
            violation_type="BOUNDS",
            arg_indices=[index_arg],
            check_expr=f"0 <= arg_{index_arg} < {size_ref}"
        )
    
    @classmethod
    def shape_compatible(cls, arg1: int, arg2: int, description: str) -> Precondition:
        """Two tensors must have compatible shapes."""
        return cls(
            condition=description,
            violation_type="VALUE_ERROR",
            arg_indices=[arg1, arg2]
        )
    
    @classmethod
    def positive_arg(cls, arg_index: int, arg_name: str = "size") -> Precondition:
        """Argument must be positive."""
        return cls(
            condition=f"{arg_name} > 0",
            violation_type="VALUE_ERROR",
            arg_indices=[arg_index],
            required_interval=Interval.positive(),
        )
    
    def to_barrier(self, subject_name: str, location: str | None = None) -> Barrier:
        """Convert this precondition to a barrier for checking."""
        return Barrier(
            barrier_type=self.violation_type,
            condition=self.condition,
            subject_name=subject_name,
            required_interval=self.required_interval,
            location=location,
        )


@dataclass 
class Postcondition:
    """A condition guaranteed after successful function execution - establishes value bounds."""
    condition: str                    # Human-readable description
    guarantee_type: str               # What aspect is guaranteed
    applies_to: str = "return"        # "return" or specific arg
    
    # The guaranteed interval for the result
    guaranteed_interval: Interval | None = None
    guaranteed_nullability: Nullability | None = None
    guaranteed_shape: ShapeSpec | None = None
    
    @classmethod
    def value_in_range(cls, min_val: float, max_val: float) -> Postcondition:
        """Guarantee that result is within a range."""
        return cls(
            condition=f"result ∈ [{min_val}, {max_val}]",
            guarantee_type="value_bounds",
            guaranteed_interval=Interval.between(min_val, max_val),
        )
    
    @classmethod
    def non_negative(cls) -> Postcondition:
        """Guarantee that result is non-negative."""
        return cls(
            condition="result >= 0",
            guarantee_type="value_bounds",
            guaranteed_interval=Interval.non_negative(),
        )
    
    @classmethod
    def non_zero(cls) -> Postcondition:
        """Guarantee that result is non-zero."""
        return cls(
            condition="result != 0",
            guarantee_type="value_bounds",
            guaranteed_interval=Interval.non_zero(),
        )
    
    @classmethod
    def unit_interval(cls) -> Postcondition:
        """Guarantee that result is in [0, 1]."""
        return cls(
            condition="result ∈ [0, 1]",
            guarantee_type="value_bounds",
            guaranteed_interval=Interval.unit_interval(),
        )
    
    @classmethod
    def cosine_range(cls) -> Postcondition:
        """Guarantee that result is in [-1, 1] (cosine similarity)."""
        return cls(
            condition="result ∈ [-1, 1]",
            guarantee_type="value_bounds",
            guaranteed_interval=Interval.cosine_similarity_range(),
        )


@dataclass
class ExceptionSpec:
    """Specification of an exception a function can raise."""
    exception_type: str              # Exception class name
    condition: str                   # When it's raised
    is_bug: bool = True              # Is this condition typically a bug?
    can_be_caught: bool = True       # Can caller reasonably catch this?


@dataclass
class TaintSpec:
    """How taint propagates through a function."""
    behavior: TaintBehavior = TaintBehavior.NEUTRAL
    
    # For PROPAGATE: which args' taint flows to output
    taint_sources: list[int] = field(default_factory=list)
    
    # For SANITIZE: what bug types it sanitizes
    sanitizes_for: list[str] = field(default_factory=list)
    
    # For SINK: what bug type if tainted input reaches
    sink_type: str | None = None
    sink_arg_indices: list[int] = field(default_factory=list)


@dataclass
class TypeSpec:
    """Type specification for return values."""
    base_type: str                    # e.g., "Tensor", "list", "int"
    generic_args: list[str] = field(default_factory=list)  # e.g., ["int"] for list[int]
    union_types: list[str] = field(default_factory=list)   # For Union types
    is_optional: bool = False         # Is Optional[T]


# =============================================================================
# LIBRARY CONTRACT - The Main Contract Class
# =============================================================================

@dataclass
class LibraryContract:
    """
    Complete specification for a library function's behavior.
    
    A contract is a barrier specification that defines:
    - What the function returns (type, shape, value bounds)
    - What preconditions must hold (barriers to check before call)
    - What postconditions are guaranteed (barriers established after call)
    - How taint flows through the function
    
    The key insight: postconditions establish value bounds that can be
    propagated through arithmetic and later used to prove barriers safe.
    
    Example:
        cosine_similarity contract has postcondition: result ∈ [-1, 1]
        This enables proving: cosine_similarity(x, y) - 3 ≠ 0
        Because: [-1, 1] - 3 = [-4, -2], and 0 ∉ [-4, -2]
    """
    
    # Identification
    module: str                       # e.g., "torch", "numpy"
    function: str                     # e.g., "randn", "Tensor.__getitem__"
    signature: str = ""               # Optional signature string
    
    # Return specification
    return_type: TypeSpec | None = None
    return_nullability: Nullability = Nullability.NEVER
    return_shape: ShapeSpec | None = None
    
    # Value bounds for return value (key for deferred barrier checking)
    return_interval: Interval = field(default_factory=Interval.unknown)
    
    # Legacy bounds (converted to return_interval)
    bounds_info: BoundsSpec | None = None
    
    # Preconditions (barriers to check)
    preconditions: list[Precondition] = field(default_factory=list)
    
    # Postconditions (barriers established)
    postconditions: list[Postcondition] = field(default_factory=list)
    
    # Exceptions
    exceptions: list[ExceptionSpec] = field(default_factory=list)
    
    # Side effects
    modifies_args: list[int] = field(default_factory=list)
    pure: bool = True                 # No side effects
    
    # Security
    taint_spec: TaintSpec = field(default_factory=TaintSpec)
    unsafe_with_user_input: bool = False
    
    # Documentation
    description: str = ""
    
    # Barrier strength of this contract's guarantees
    barrier_strength: BarrierStrength = BarrierStrength.STRONG
    
    def __post_init__(self):
        """Initialize return_interval from bounds_info if provided."""
        if self.bounds_info is not None and self.return_interval.min_val is None and self.return_interval.max_val is None:
            self.return_interval = self.bounds_info.get_interval()
        
        # Also extract from postconditions
        for post in self.postconditions:
            if post.guaranteed_interval is not None and post.applies_to == "return":
                self.return_interval = post.guaranteed_interval
                break
    
    def get_full_name(self) -> str:
        """Get fully qualified function name."""
        return f"{self.module}.{self.function}"
    
    def has_precondition_for(self, bug_type: str) -> bool:
        """Check if there's a precondition for a specific bug type."""
        return any(p.violation_type == bug_type for p in self.preconditions)
    
    def can_raise(self, exception_type: str) -> bool:
        """Check if function can raise a specific exception."""
        return any(e.exception_type == exception_type for e in self.exceptions)
    
    def is_taint_sink(self) -> bool:
        """Check if function is a taint sink."""
        return self.taint_spec.behavior == TaintBehavior.SINK
    
    def get_return_interval(self) -> Interval:
        """Get the interval for return values."""
        return self.return_interval
    
    def creates_barrier_for(self, bug_type: str) -> bool:
        """Check if this contract creates a barrier for a bug type."""
        return any(p.violation_type == bug_type for p in self.preconditions)
    
    def apply_to_abstract_value(self, args: list[AbstractValue]) -> AbstractValue:
        """
        Apply this contract to create an abstract value for the result.
        
        This is the key function for deferred barrier checking:
        it propagates interval information from the contract to the result.
        """
        return AbstractValue(
            name=f"{self.get_full_name()}(...)",
            interval=self.return_interval,
            nullability=self.return_nullability,
            source_contract=self.get_full_name(),
            barrier_strength=self.barrier_strength,
        )


# =============================================================================
# CONTRACT REGISTRY
# =============================================================================

class ContractRegistry:
    """Registry of library contracts for lookup during analysis."""
    
    def __init__(self):
        self._contracts: dict[str, LibraryContract] = {}
        self._module_contracts: dict[str, list[LibraryContract]] = {}
    
    def register(self, contract: LibraryContract) -> None:
        """Register a contract."""
        full_name = contract.get_full_name()
        self._contracts[full_name] = contract
        
        if contract.module not in self._module_contracts:
            self._module_contracts[contract.module] = []
        self._module_contracts[contract.module].append(contract)
    
    def get(self, full_name: str) -> LibraryContract | None:
        """Get a contract by full name (e.g., 'torch.randn')."""
        return self._contracts.get(full_name)
    
    def get_by_module_function(self, module: str, function: str) -> LibraryContract | None:
        """Get a contract by module and function name."""
        return self.get(f"{module}.{function}")
    
    def get_module_contracts(self, module: str) -> list[LibraryContract]:
        """Get all contracts for a module."""
        return self._module_contracts.get(module, [])
    
    def has_contract(self, full_name: str) -> bool:
        """Check if a contract exists."""
        return full_name in self._contracts
    
    def all_contracts(self) -> list[LibraryContract]:
        """Get all registered contracts."""
        return list(self._contracts.values())
    
    def __len__(self) -> int:
        return len(self._contracts)
    
    def __contains__(self, full_name: str) -> bool:
        return full_name in self._contracts


# =============================================================================
# ABSTRACT VALUE TRACKER - For Deferred Barrier Resolution
# =============================================================================

class AbstractValueTracker:
    """
    Tracks abstract values through computation for deferred barrier checking.
    
    Example usage:
        tracker = AbstractValueTracker(registry)
        
        # cosine_similarity returns [-1, 1]
        cos_val = tracker.apply_call("torch.cosine_similarity", [x, y])
        # cos_val.interval = Interval(-1, 1)
        
        # Arithmetic propagates bounds
        diff = tracker.apply_subtract(cos_val, 3)
        # diff.interval = Interval(-4, -2)
        
        # Division barrier check
        result = tracker.check_division_barrier(diff)
        # Returns DEFINITELY_SAFE because 0 ∉ [-4, -2]
    """
    
    def __init__(self, registry: ContractRegistry | None = None):
        self.registry = registry or get_global_registry()
        self.values: dict[str, AbstractValue] = {}
        self.deferred_barriers: list[DeferredBarrier] = []
    
    def track(self, name: str, value: AbstractValue) -> None:
        """Track a value by name."""
        self.values[name] = value
    
    def get(self, name: str) -> AbstractValue | None:
        """Get a tracked value."""
        return self.values.get(name)
    
    def apply_call(self, func_name: str, args: list[AbstractValue]) -> AbstractValue:
        """
        Apply a function call using its contract.
        
        Returns an abstract value with interval from the contract.
        """
        contract = self.registry.get(func_name)
        if contract is None:
            return AbstractValue(name=f"{func_name}(...)", interval=Interval.unknown())
        
        return contract.apply_to_abstract_value(args)
    
    def apply_add(self, left: AbstractValue, right: AbstractValue | float) -> AbstractValue:
        """Apply addition with interval propagation."""
        if isinstance(right, (int, float)):
            new_interval = left.interval + right
        else:
            new_interval = left.interval + right.interval
        
        return left.with_interval(new_interval)
    
    def apply_subtract(self, left: AbstractValue, right: AbstractValue | float) -> AbstractValue:
        """Apply subtraction with interval propagation."""
        if isinstance(right, (int, float)):
            new_interval = left.interval - right
        else:
            new_interval = left.interval - right.interval
        
        return left.with_interval(new_interval)
    
    def apply_multiply(self, left: AbstractValue, right: AbstractValue | float) -> AbstractValue:
        """Apply multiplication with interval propagation."""
        if isinstance(right, (int, float)):
            new_interval = left.interval * right
        else:
            new_interval = left.interval * right.interval
        
        return left.with_interval(new_interval)
    
    def check_division_barrier(self, divisor: AbstractValue) -> BarrierResult:
        """
        Check the division barrier for a divisor.
        
        This is where deferred checking shines:
        If divisor came from cosine_similarity(x,y) - 3,
        its interval is [-4, -2], which doesn't contain 0,
        so we can prove the division is safe.
        """
        barrier = Barrier(
            barrier_type="DIV_ZERO",
            condition="divisor != 0",
            subject_name=divisor.name,
        )
        return barrier.check(divisor)
    
    def check_null_barrier(self, value: AbstractValue) -> BarrierResult:
        """Check the null pointer barrier."""
        barrier = Barrier(
            barrier_type="NULL_PTR",
            condition="value is not None",
            subject_name=value.name,
        )
        return barrier.check(value)
    
    def check_bounds_barrier(self, index: AbstractValue, size: int) -> BarrierResult:
        """Check bounds barrier for array/tensor indexing."""
        barrier = Barrier(
            barrier_type="BOUNDS",
            condition=f"0 <= index < {size}",
            subject_name=index.name,
            required_interval=Interval.between(0, size - 1),
        )
        return barrier.check(index)


# =============================================================================
# GLOBAL REGISTRY
# =============================================================================

_global_registry = ContractRegistry()


def get_global_registry() -> ContractRegistry:
    """Get the global contract registry."""
    return _global_registry


def register_contract(contract: LibraryContract) -> None:
    """Register a contract in the global registry."""
    _global_registry.register(contract)


def get_contract(full_name: str) -> LibraryContract | None:
    """Get a contract from the global registry."""
    return _global_registry.get(full_name)


def get_tracker() -> AbstractValueTracker:
    """Get a new abstract value tracker using the global registry."""
    return AbstractValueTracker(_global_registry)
