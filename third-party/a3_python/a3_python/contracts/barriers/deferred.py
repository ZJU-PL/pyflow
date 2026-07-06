"""
Deferred Barriers and Constraints

This module implements the core concept of DEFERRED BARRIERS:
constraints that are recorded when library functions are called
and can be used later to prove safety properties.

Key Insight:
    When we call `cosine_similarity(x, y)`, we don't immediately
    need to know the result is in [-1, 1]. But later, when we
    compute `result - 3` and divide by it, we can use the
    deferred barrier to prove `result - 3 ≠ 0`.

The deferred barrier tracks:
    1. The original constraint (e.g., value in [-1, 1])
    2. All transformations applied (e.g., subtract 3)
    3. The current derived constraint (e.g., value in [-4, -2])
    4. Whether this proves safety properties (e.g., excludes zero)

Integration with 5-Layer Barrier Synthesis:
    Layer 1-2 (SOS/SDP): Deferred barriers become polynomial constraints
    Layer 3 (CEGAR): Deferred barriers provide refinement predicates
    Layer 4 (ICE): Deferred barriers generate training samples
    Layer 5 (IC3): Deferred barriers encode as CHC clauses
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import (
    Optional, Union, List, Dict, Any, Tuple, 
    Callable, FrozenSet, Set
)
from enum import Enum, auto
import math

from .intervals import Interval


# =============================================================================
# Constraint Kinds
# =============================================================================

class ConstraintKind(Enum):
    """Types of constraints that can be deferred."""
    
    # Value range constraints
    INTERVAL = auto()          # Value in [a, b]
    POSITIVE = auto()          # Value > 0
    NON_NEGATIVE = auto()      # Value >= 0
    NEGATIVE = auto()          # Value < 0
    NON_POSITIVE = auto()      # Value <= 0
    NON_ZERO = auto()          # Value != 0
    
    # PyTorch-specific constraints
    DEVICE_MATCH = auto()      # Tensors on same device
    SHAPE_COMPATIBLE = auto()  # Shapes are broadcast-compatible
    DTYPE_COMPATIBLE = auto()  # DTypes are compatible
    CONTIGUOUS = auto()        # Tensor is contiguous
    
    # Semantic constraints
    PROBABILITY = auto()       # Value in [0, 1], sum to 1
    NORMALIZED = auto()        # L2 norm = 1
    UNIT_VECTOR = auto()       # Elements in [-1, 1], norm = 1
    ONE_HOT = auto()           # One 1 per row, rest 0
    
    # Linear algebra constraints
    POSITIVE_DEFINITE = auto()
    SYMMETRIC = auto()
    ORTHOGONAL = auto()
    FULL_RANK = auto()
    
    # Custom constraint
    CUSTOM = auto()


# =============================================================================
# Barrier Strength (How confident are we?)
# =============================================================================

class BarrierStrength(Enum):
    """
    Strength of a barrier proof.
    
    Ordered from weakest to strongest:
    """
    NONE = 0           # No barrier found
    HEURISTIC = 1      # Based on patterns/naming
    TYPE_BASED = 2     # Based on type information
    INTERVAL = 3       # Proven by interval analysis
    CONTRACT = 4       # Proven by library contract
    DEFERRED = 5       # Proven by deferred barrier propagation
    SYMBOLIC = 6       # Proven by symbolic execution + SMT
    SOS = 7            # Proven by SOS/SDP
    CEGAR = 8          # Proven by CEGAR refinement
    IC3 = 9            # Proven by IC3/PDR
    
    def __lt__(self, other: BarrierStrength) -> bool:
        return self.value < other.value
    
    def __le__(self, other: BarrierStrength) -> bool:
        return self.value <= other.value
    
    def is_sufficient(self) -> bool:
        """Check if this strength is sufficient for reporting as safe."""
        return self.value >= BarrierStrength.INTERVAL.value


# =============================================================================
# Barrier Result
# =============================================================================

class BarrierResult(Enum):
    """Result of a barrier check."""
    
    SAFE = auto()              # Definitely safe
    POTENTIALLY_UNSAFE = auto() # Might be unsafe
    DEFINITELY_UNSAFE = auto() # Definitely unsafe (counterexample found)
    UNKNOWN = auto()           # Cannot determine


@dataclass
class BarrierProof:
    """
    A proof that a safety property holds.
    
    Contains:
    - The safety property being proven
    - The barrier that proves it
    - The strength of the proof
    - Human-readable explanation
    """
    property_name: str
    result: BarrierResult
    strength: BarrierStrength
    explanation: str
    barrier: Optional[DeferredBarrier] = None
    witness_interval: Optional[Interval] = None
    
    @classmethod
    def safe(cls, property_name: str, barrier: DeferredBarrier, 
             strength: BarrierStrength = BarrierStrength.DEFERRED) -> BarrierProof:
        """Create a SAFE proof."""
        return cls(
            property_name=property_name,
            result=BarrierResult.SAFE,
            strength=strength,
            explanation=f"Proven safe by {strength.name}: {barrier.current_interval}",
            barrier=barrier,
            witness_interval=barrier.current_interval,
        )
    
    @classmethod
    def unsafe(cls, property_name: str, explanation: str) -> BarrierProof:
        """Create an UNSAFE proof."""
        return cls(
            property_name=property_name,
            result=BarrierResult.POTENTIALLY_UNSAFE,
            strength=BarrierStrength.NONE,
            explanation=explanation,
        )
    
    @classmethod
    def unknown(cls, property_name: str) -> BarrierProof:
        """Create an UNKNOWN result."""
        return cls(
            property_name=property_name,
            result=BarrierResult.UNKNOWN,
            strength=BarrierStrength.NONE,
            explanation="Could not determine safety",
        )
    
    @property
    def is_safe(self) -> bool:
        return self.result == BarrierResult.SAFE
    
    @property
    def is_unsafe(self) -> bool:
        return self.result in (BarrierResult.POTENTIALLY_UNSAFE, BarrierResult.DEFINITELY_UNSAFE)
    
    def __repr__(self) -> str:
        return f"BarrierProof({self.property_name}: {self.result.name}, {self.strength.name})"


# =============================================================================
# Transformation Trace
# =============================================================================

@dataclass(frozen=True)
class Transformation:
    """A single transformation applied to a value."""
    operation: str  # '+', '-', '*', '/', 'neg', 'abs', etc.
    operand: Optional[Any] = None
    operand_interval: Optional[Interval] = None
    
    def __str__(self) -> str:
        if self.operand is not None:
            return f"{self.operation} {self.operand}"
        return self.operation


@dataclass
class TransformationTrace:
    """
    Trace of transformations applied to a value.
    
    Used for:
    - Debugging: understanding how a constraint evolved
    - Explanation: generating human-readable proofs
    - Refinement: identifying which transformations lose precision
    """
    transformations: List[Transformation] = field(default_factory=list)
    
    def add(self, op: str, operand: Any = None, operand_interval: Interval = None) -> TransformationTrace:
        """Add a transformation (returns new trace)."""
        new_trace = TransformationTrace(self.transformations.copy())
        new_trace.transformations.append(Transformation(op, operand, operand_interval))
        return new_trace
    
    def __str__(self) -> str:
        if not self.transformations:
            return "identity"
        return " → ".join(str(t) for t in self.transformations)
    
    def __repr__(self) -> str:
        return f"TransformationTrace({self})"


# =============================================================================
# Deferred Constraint
# =============================================================================

@dataclass
class DeferredConstraint:
    """
    A constraint that may be useful later.
    
    More general than DeferredBarrier - can represent
    non-interval constraints like device matching.
    """
    kind: ConstraintKind
    description: str
    variables: FrozenSet[str] = field(default_factory=frozenset)
    
    # For interval constraints
    interval: Optional[Interval] = None
    
    # For device constraints
    device_a: Optional[str] = None
    device_b: Optional[str] = None
    
    # For shape constraints
    shape_a: Optional[Any] = None
    shape_b: Optional[Any] = None
    
    # Source information
    source_function: Optional[str] = None
    source_location: Optional[str] = None
    
    @classmethod
    def interval_constraint(cls, var: str, interval: Interval, 
                           source: str = None) -> DeferredConstraint:
        """Create an interval constraint."""
        return cls(
            kind=ConstraintKind.INTERVAL,
            description=f"{var} ∈ {interval}",
            variables=frozenset([var]),
            interval=interval,
            source_function=source,
        )
    
    @classmethod
    def device_match(cls, var_a: str, device_a: str, 
                     var_b: str, device_b: str) -> DeferredConstraint:
        """Create a device matching constraint."""
        return cls(
            kind=ConstraintKind.DEVICE_MATCH,
            description=f"{var_a}.device ({device_a}) == {var_b}.device ({device_b})",
            variables=frozenset([var_a, var_b]),
            device_a=device_a,
            device_b=device_b,
        )
    
    @classmethod
    def shape_compatible(cls, var_a: str, shape_a: Any,
                         var_b: str, shape_b: Any) -> DeferredConstraint:
        """Create a shape compatibility constraint."""
        return cls(
            kind=ConstraintKind.SHAPE_COMPATIBLE,
            description=f"{var_a}.shape ({shape_a}) compatible with {var_b}.shape ({shape_b})",
            variables=frozenset([var_a, var_b]),
            shape_a=shape_a,
            shape_b=shape_b,
        )
    
    @classmethod
    def non_zero(cls, var: str, source: str = None) -> DeferredConstraint:
        """Create a non-zero constraint."""
        return cls(
            kind=ConstraintKind.NON_ZERO,
            description=f"{var} ≠ 0",
            variables=frozenset([var]),
            source_function=source,
        )
    
    @classmethod
    def positive(cls, var: str, source: str = None) -> DeferredConstraint:
        """Create a positive constraint."""
        return cls(
            kind=ConstraintKind.POSITIVE,
            description=f"{var} > 0",
            variables=frozenset([var]),
            interval=Interval.positive(),
            source_function=source,
        )
    
    def is_satisfied(self) -> Optional[bool]:
        """
        Check if constraint is satisfied.
        
        Returns:
            True if definitely satisfied
            False if definitely violated
            None if unknown
        """
        if self.kind == ConstraintKind.INTERVAL:
            # Always satisfied for interval (defines the range)
            return True
        
        if self.kind == ConstraintKind.DEVICE_MATCH:
            if self.device_a and self.device_b:
                return self.device_a == self.device_b
            return None
        
        if self.kind == ConstraintKind.NON_ZERO:
            if self.interval:
                return self.interval.excludes_zero()
            return None
        
        return None
    
    def __repr__(self) -> str:
        return f"DeferredConstraint({self.kind.name}: {self.description})"


# =============================================================================
# Deferred Barrier
# =============================================================================

@dataclass
class DeferredBarrier:
    """
    A barrier constraint that propagates through transformations.
    
    This is the core abstraction for deferred constraint propagation.
    
    A DeferredBarrier tracks:
    1. source_interval: The original interval from a library contract
    2. current_interval: The interval after all transformations
    3. trace: The sequence of transformations applied
    4. variable: The variable this barrier constrains
    
    Key Methods:
    - add/subtract/multiply/divide: Apply arithmetic transformations
    - proves_nonzero(): Check if division is safe
    - proves_positive(): Check if log/sqrt is safe
    - to_barrier_polynomial(): Generate SOS polynomial
    
    Example:
        >>> barrier = DeferredBarrier.from_interval("sim", Interval(-1, 1))
        >>> barrier.current_interval
        [-1, 1]
        >>> barrier = barrier.subtract(3)
        >>> barrier.current_interval
        [-4, -2]
        >>> barrier.proves_nonzero()
        True  # Division by this value is SAFE
    """
    
    variable: str
    source_interval: Interval
    current_interval: Interval
    trace: TransformationTrace = field(default_factory=TransformationTrace)
    
    # Contract information
    source_contract: Optional[str] = None
    source_function: Optional[str] = None
    source_module: Optional[str] = None
    
    # Location information
    creation_location: Optional[str] = None
    
    # Strength tracking
    strength: BarrierStrength = BarrierStrength.CONTRACT
    
    # =========================================================================
    # Constructors
    # =========================================================================
    
    @classmethod
    def from_interval(cls, variable: str, interval: Interval,
                      source_function: str = None) -> DeferredBarrier:
        """Create barrier from an interval constraint."""
        return cls(
            variable=variable,
            source_interval=interval,
            current_interval=interval,
            source_function=source_function,
        )
    
    @classmethod
    def from_contract(cls, variable: str, contract_name: str,
                      interval: Interval) -> DeferredBarrier:
        """Create barrier from a library contract."""
        return cls(
            variable=variable,
            source_interval=interval,
            current_interval=interval,
            source_contract=contract_name,
            strength=BarrierStrength.CONTRACT,
        )
    
    @classmethod
    def positive(cls, variable: str, source: str = None) -> DeferredBarrier:
        """Create barrier for positive values."""
        return cls.from_interval(variable, Interval.positive(), source)
    
    @classmethod
    def non_negative(cls, variable: str, source: str = None) -> DeferredBarrier:
        """Create barrier for non-negative values."""
        return cls.from_interval(variable, Interval.non_negative(), source)
    
    @classmethod
    def unit(cls, variable: str, source: str = None) -> DeferredBarrier:
        """Create barrier for values in [0, 1]."""
        return cls.from_interval(variable, Interval.unit(), source)
    
    @classmethod
    def symmetric_unit(cls, variable: str, source: str = None) -> DeferredBarrier:
        """Create barrier for values in [-1, 1]."""
        return cls.from_interval(variable, Interval.symmetric_unit(), source)
    
    @classmethod
    def bounded(cls, variable: str, lo: float, hi: float,
                source: str = None) -> DeferredBarrier:
        """Create barrier for values in [lo, hi]."""
        return cls.from_interval(variable, Interval(lo, hi), source)
    
    # =========================================================================
    # Arithmetic Transformations
    # =========================================================================
    
    def _transform(self, new_interval: Interval, op: str, 
                   operand: Any = None) -> DeferredBarrier:
        """Apply a transformation and return new barrier."""
        operand_interval = None
        if isinstance(operand, Interval):
            operand_interval = operand
        elif isinstance(operand, (int, float)):
            operand_interval = Interval.point(float(operand))
        
        return DeferredBarrier(
            variable=self.variable,
            source_interval=self.source_interval,
            current_interval=new_interval,
            trace=self.trace.add(op, operand, operand_interval),
            source_contract=self.source_contract,
            source_function=self.source_function,
            source_module=self.source_module,
            creation_location=self.creation_location,
            strength=self.strength,
        )
    
    def add(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        """Add a value or interval."""
        if isinstance(other, DeferredBarrier):
            other = other.current_interval
        elif isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        return self._transform(self.current_interval + other, '+', other)
    
    def subtract(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        """Subtract a value or interval."""
        if isinstance(other, DeferredBarrier):
            other = other.current_interval
        elif isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        return self._transform(self.current_interval - other, '-', other)
    
    def multiply(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        """Multiply by a value or interval."""
        if isinstance(other, DeferredBarrier):
            other = other.current_interval
        elif isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        return self._transform(self.current_interval * other, '*', other)
    
    def divide(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        """Divide by a value or interval."""
        if isinstance(other, DeferredBarrier):
            other = other.current_interval
        elif isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        return self._transform(self.current_interval / other, '/', other)
    
    def negate(self) -> DeferredBarrier:
        """Negate the value."""
        return self._transform(-self.current_interval, 'neg')
    
    def abs(self) -> DeferredBarrier:
        """Take absolute value."""
        return self._transform(abs(self.current_interval), 'abs')
    
    def square(self) -> DeferredBarrier:
        """Square the value."""
        return self._transform(self.current_interval ** 2, '**2')
    
    def sqrt(self) -> DeferredBarrier:
        """Take square root (requires non-negative)."""
        return self._transform(self.current_interval.sqrt(), 'sqrt')
    
    def exp(self) -> DeferredBarrier:
        """Exponentiate."""
        return self._transform(self.current_interval.exp(), 'exp')
    
    def log(self) -> DeferredBarrier:
        """Take natural log (requires positive)."""
        return self._transform(self.current_interval.log(), 'log')
    
    def clamp(self, lo: float, hi: float) -> DeferredBarrier:
        """Clamp to [lo, hi]."""
        return self._transform(self.current_interval.clamp(lo, hi), 'clamp', (lo, hi))
    
    def relu(self) -> DeferredBarrier:
        """Apply ReLU."""
        return self._transform(self.current_interval.relu(), 'relu')
    
    def sigmoid(self) -> DeferredBarrier:
        """Apply sigmoid."""
        return self._transform(self.current_interval.sigmoid(), 'sigmoid')
    
    def tanh(self) -> DeferredBarrier:
        """Apply tanh."""
        return self._transform(self.current_interval.tanh(), 'tanh')
    
    # Operator overloads
    def __add__(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        return self.add(other)
    
    def __radd__(self, other: Union[float, Interval]) -> DeferredBarrier:
        return self.add(other)
    
    def __sub__(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        return self.subtract(other)
    
    def __rsub__(self, other: Union[float, Interval]) -> DeferredBarrier:
        if isinstance(other, (int, float)):
            other = Interval.point(float(other))
        return DeferredBarrier.from_interval(
            self.variable, other
        ).subtract(self.current_interval)
    
    def __mul__(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        return self.multiply(other)
    
    def __rmul__(self, other: Union[float, Interval]) -> DeferredBarrier:
        return self.multiply(other)
    
    def __truediv__(self, other: Union[float, Interval, DeferredBarrier]) -> DeferredBarrier:
        return self.divide(other)
    
    def __neg__(self) -> DeferredBarrier:
        return self.negate()
    
    def __abs__(self) -> DeferredBarrier:
        return self.abs()
    
    # =========================================================================
    # Safety Checks (Barrier Activation)
    # =========================================================================
    
    def proves_nonzero(self) -> bool:
        """
        Check if this barrier proves the value is non-zero.
        
        This is THE KEY CHECK for division safety.
        
        If proves_nonzero() returns True, division by this value is SAFE.
        """
        return self.current_interval.excludes_zero()
    
    def proves_positive(self) -> bool:
        """
        Check if this barrier proves the value is positive.
        
        Key for: log(), sqrt() on values that must be positive.
        """
        return self.current_interval.is_strictly_positive()
    
    def proves_non_negative(self) -> bool:
        """Check if value is proven non-negative."""
        return self.current_interval.is_non_negative()
    
    def proves_in_range(self, lo: float, hi: float) -> bool:
        """Check if value is proven in [lo, hi]."""
        return self.current_interval.lo >= lo and self.current_interval.hi <= hi
    
    def proves_lt(self, value: float) -> bool:
        """Check if value is proven < value."""
        return self.current_interval.hi < value
    
    def proves_le(self, value: float) -> bool:
        """Check if value is proven <= value."""
        return self.current_interval.hi <= value
    
    def proves_gt(self, value: float) -> bool:
        """Check if value is proven > value."""
        return self.current_interval.lo > value
    
    def proves_ge(self, value: float) -> bool:
        """Check if value is proven >= value."""
        return self.current_interval.lo >= value
    
    def check_division_safety(self) -> BarrierProof:
        """
        Check if using this value as a divisor is safe.
        
        Returns a BarrierProof with the result.
        """
        if self.proves_nonzero():
            return BarrierProof.safe("division", self, self.strength)
        
        if self.current_interval.is_bottom:
            return BarrierProof.safe("division", self, BarrierStrength.INTERVAL)
        
        return BarrierProof.unsafe(
            "division",
            f"Cannot prove {self.variable} ≠ 0; interval is {self.current_interval}"
        )
    
    def check_sqrt_safety(self) -> BarrierProof:
        """Check if sqrt() is safe (requires non-negative)."""
        if self.proves_non_negative():
            return BarrierProof.safe("sqrt", self, self.strength)
        
        return BarrierProof.unsafe(
            "sqrt",
            f"Cannot prove {self.variable} >= 0; interval is {self.current_interval}"
        )
    
    def check_log_safety(self) -> BarrierProof:
        """Check if log() is safe (requires positive)."""
        if self.proves_positive():
            return BarrierProof.safe("log", self, self.strength)
        
        return BarrierProof.unsafe(
            "log",
            f"Cannot prove {self.variable} > 0; interval is {self.current_interval}"
        )
    
    # =========================================================================
    # Barrier Polynomial Generation (for SOS/SDP)
    # =========================================================================
    
    def to_barrier_polynomial(self, var_symbol: str = "x") -> Optional[str]:
        """
        Generate barrier polynomial for SOS verification.
        
        For interval [a, b], the barrier is:
            B(x) = (x - a)(b - x)
        
        which is >= 0 iff x in [a, b].
        """
        if not self.current_interval.is_bounded:
            return None
        
        a, b = self.current_interval.lo, self.current_interval.hi
        return f"({var_symbol} - {a}) * ({b} - {var_symbol})"
    
    def to_smt_constraint(self, var_symbol: str = "x") -> str:
        """Generate SMT constraint for Z3."""
        return self.current_interval.to_smt_constraint(var_symbol)
    
    def to_chc_clause(self, predicate_name: str, var_symbol: str = "x") -> str:
        """Generate CHC clause for IC3/Spacer."""
        constraint = self.to_smt_constraint(var_symbol)
        return f"(rule (=> true (and ({predicate_name} {var_symbol}) {constraint})))"
    
    # =========================================================================
    # ICE Sample Generation (for Layer 4)
    # =========================================================================
    
    def to_ice_samples(self, var: str) -> Dict[str, List[Dict[str, float]]]:
        """
        Generate ICE (Implication-Counterexample-Equivalence) samples.
        
        Returns:
            {
                'positive': [{var: value}, ...],  # Values that satisfy barrier
                'negative': [{var: value}, ...],  # Values that violate barrier
                'implications': [(pre, post), ...]  # State transitions
            }
        """
        interval = self.current_interval
        
        if not interval.is_bounded or interval.is_bottom:
            return {'positive': [], 'negative': [], 'implications': []}
        
        positive = []
        negative = []
        
        # Add boundary points
        if not math.isinf(interval.lo):
            positive.append({var: interval.lo})
            negative.append({var: interval.lo - 0.001})
            negative.append({var: interval.lo - 1.0})
        
        if not math.isinf(interval.hi):
            positive.append({var: interval.hi})
            negative.append({var: interval.hi + 0.001})
            negative.append({var: interval.hi + 1.0})
        
        # Add midpoint
        positive.append({var: interval.midpoint})
        
        # Add more interior points
        if interval.width > 0:
            positive.append({var: interval.lo + interval.width * 0.25})
            positive.append({var: interval.lo + interval.width * 0.75})
        
        return {
            'positive': positive,
            'negative': negative,
            'implications': [],
        }
    
    # =========================================================================
    # Representation
    # =========================================================================
    
    def __repr__(self) -> str:
        parts = [
            f"var={self.variable}",
            f"interval={self.current_interval}",
        ]
        if self.source_contract:
            parts.append(f"from={self.source_contract}")
        if len(self.trace.transformations) > 0:
            parts.append(f"trace={self.trace}")
        return f"DeferredBarrier({', '.join(parts)})"
    
    def __str__(self) -> str:
        return f"{self.variable} ∈ {self.current_interval}"
    
    def explain(self) -> str:
        """Generate human-readable explanation of this barrier."""
        lines = [
            f"Barrier for variable: {self.variable}",
            f"Current interval: {self.current_interval}",
        ]
        
        if self.source_contract:
            lines.append(f"Source: {self.source_contract}")
            lines.append(f"Original interval: {self.source_interval}")
        
        if self.trace.transformations:
            lines.append(f"Transformations: {self.trace}")
        
        lines.append(f"Strength: {self.strength.name}")
        
        # Safety properties
        safety = []
        if self.proves_nonzero():
            safety.append("division-safe (≠0)")
        if self.proves_positive():
            safety.append("log/sqrt-safe (>0)")
        if self.proves_non_negative():
            safety.append("sqrt-safe (≥0)")
        
        if safety:
            lines.append(f"Proves: {', '.join(safety)}")
        
        return "\n".join(lines)


# =============================================================================
# Device Barrier (PyTorch-specific)
# =============================================================================

@dataclass
class DeviceBarrier:
    """
    A barrier specifically for device compatibility checking.
    
    This is a PyTorch-specific barrier that tracks whether tensors
    are on compatible devices.
    
    Operations on tensors from different devices cause runtime errors:
        tensor_cpu + tensor_cuda  # RuntimeError!
    
    The DeviceBarrier tracks:
    - Known devices for variables
    - Compatibility constraints
    - Potential violations
    
    Example:
        >>> barrier = DeviceBarrier()
        >>> barrier.set_device("a", Device.cpu())
        >>> barrier.set_device("b", Device.cuda(0))
        >>> barrier.check_compatible("a", "b")
        DeviceCompatibilityResult(compatible=False, error="Device mismatch...")
    """
    
    # Variable -> Device mapping
    devices: Dict[str, "Device"] = field(default_factory=dict)
    
    # Recorded constraints
    constraints: List[DeferredConstraint] = field(default_factory=list)
    
    # Known violations
    violations: List[str] = field(default_factory=list)
    
    def set_device(self, variable: str, device: "Device") -> None:
        """Record a variable's device."""
        from .abstract_values import Device
        self.devices[variable] = device
    
    def get_device(self, variable: str) -> Optional["Device"]:
        """Get a variable's known device."""
        return self.devices.get(variable)
    
    def check_compatible(self, var_a: str, var_b: str) -> Tuple[bool, Optional[str]]:
        """
        Check if two variables are on compatible devices.
        
        Returns:
            (is_safe, error_message)
        """
        from .abstract_values import Device
        
        dev_a = self.devices.get(var_a)
        dev_b = self.devices.get(var_b)
        
        if dev_a is None or dev_b is None:
            # Unknown device - can't prove safety
            return (False, f"Unknown device for {var_a if dev_a is None else var_b}")
        
        if dev_a.compatible_with(dev_b):
            return (True, None)
        
        # Record violation
        error = f"Device mismatch: {var_a} on {dev_a}, {var_b} on {dev_b}"
        self.violations.append(error)
        
        # Record constraint for later analysis
        self.constraints.append(DeferredConstraint.device_match(
            var_a, str(dev_a), var_b, str(dev_b)
        ))
        
        return (False, error)
    
    def record_operation(self, result_var: str, operand_vars: List[str],
                         operation: str) -> Optional[str]:
        """
        Record an operation and check device compatibility.
        
        Returns error message if incompatible, None if safe.
        """
        if len(operand_vars) < 2:
            return None
        
        # All operands must be on same device
        first_var = operand_vars[0]
        first_device = self.devices.get(first_var)
        
        for var in operand_vars[1:]:
            is_safe, error = self.check_compatible(first_var, var)
            if not is_safe:
                return f"In {operation}: {error}"
        
        # Result is on same device as operands
        if first_device is not None:
            self.devices[result_var] = first_device
        
        return None
    
    def propagate_device(self, from_var: str, to_var: str) -> None:
        """Propagate device from one variable to another."""
        if from_var in self.devices:
            self.devices[to_var] = self.devices[from_var]
    
    def transfer_to(self, variable: str, device: "Device") -> None:
        """
        Model a .to(device) or .cuda() call.
        
        After this, the variable is on the target device.
        """
        self.devices[variable] = device
    
    def has_violations(self) -> bool:
        """Check if any device violations were recorded."""
        return len(self.violations) > 0
    
    def get_violations(self) -> List[str]:
        """Get all recorded violations."""
        return self.violations.copy()
    
    def __repr__(self) -> str:
        device_str = ", ".join(f"{k}:{v}" for k, v in self.devices.items())
        return f"DeviceBarrier({{{device_str}}}, violations={len(self.violations)})"
