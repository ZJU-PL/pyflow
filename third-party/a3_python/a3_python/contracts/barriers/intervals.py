"""
Interval Abstract Domain

This module provides a rigorous implementation of the interval abstract domain
for numerical analysis, with full support for:
- Extended reals (±∞)
- Arithmetic operations with sound overapproximation
- Widening for convergence guarantee
- Meet/join lattice operations

Mathematical Foundation:
    The interval domain I = {[a,b] | a,b ∈ R̄, a ≤ b} ∪ {⊥}
    where R̄ = R ∪ {-∞, +∞} is the extended reals.
    
    Galois connection: (℘(R), ⊆) ⟷ (I, ⊑)
        α(S) = [inf S, sup S]
        γ([a,b]) = {x ∈ R | a ≤ x ≤ b}

Soundness:
    For any concrete operation ⊙ and abstract operation ⊙̂:
        ∀x ∈ γ(I₁), y ∈ γ(I₂): x ⊙ y ∈ γ(I₁ ⊙̂ I₂)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import (
    Optional, Union, Tuple, List, Iterator, Callable, 
    TypeVar, Generic, Any, Sequence, overload
)
from enum import Enum, auto
from functools import total_ordering
import math
import operator


# =============================================================================
# Extended Reals
# =============================================================================

class ExtendedRealType(Enum):
    """Type of extended real number."""
    FINITE = auto()
    POSITIVE_INF = auto()
    NEGATIVE_INF = auto()
    NAN = auto()


@total_ordering
@dataclass(frozen=True, slots=True)
class ExtendedReal:
    """
    Extended real number: R ∪ {-∞, +∞, NaN}.
    
    Implements proper arithmetic on extended reals following IEEE 754
    conventions where applicable.
    
    Examples:
        >>> ExtendedReal(3.14)
        ExtendedReal(3.14)
        >>> POSITIVE_INF + ExtendedReal(1)
        ExtendedReal(+∞)
        >>> POSITIVE_INF + NEGATIVE_INF
        ExtendedReal(NaN)
    """
    _value: float
    _type: ExtendedRealType = field(default=ExtendedRealType.FINITE)
    
    def __post_init__(self):
        # Validate and normalize
        if math.isnan(self._value):
            object.__setattr__(self, '_type', ExtendedRealType.NAN)
        elif math.isinf(self._value):
            if self._value > 0:
                object.__setattr__(self, '_type', ExtendedRealType.POSITIVE_INF)
            else:
                object.__setattr__(self, '_type', ExtendedRealType.NEGATIVE_INF)
    
    @classmethod
    def from_float(cls, v: float) -> ExtendedReal:
        """Create from float, handling special values."""
        if math.isnan(v):
            return NAN
        elif v == float('inf'):
            return POSITIVE_INF
        elif v == float('-inf'):
            return NEGATIVE_INF
        return cls(v)
    
    @property
    def is_finite(self) -> bool:
        return self._type == ExtendedRealType.FINITE
    
    @property
    def is_infinite(self) -> bool:
        return self._type in (ExtendedRealType.POSITIVE_INF, ExtendedRealType.NEGATIVE_INF)
    
    @property
    def is_positive_inf(self) -> bool:
        return self._type == ExtendedRealType.POSITIVE_INF
    
    @property
    def is_negative_inf(self) -> bool:
        return self._type == ExtendedRealType.NEGATIVE_INF
    
    @property
    def is_nan(self) -> bool:
        return self._type == ExtendedRealType.NAN
    
    def to_float(self) -> float:
        """Convert to float (may be inf or nan)."""
        if self._type == ExtendedRealType.POSITIVE_INF:
            return float('inf')
        elif self._type == ExtendedRealType.NEGATIVE_INF:
            return float('-inf')
        elif self._type == ExtendedRealType.NAN:
            return float('nan')
        return self._value
    
    def __float__(self) -> float:
        return self.to_float()
    
    def __repr__(self) -> str:
        if self.is_positive_inf:
            return "ExtendedReal(+∞)"
        elif self.is_negative_inf:
            return "ExtendedReal(-∞)"
        elif self.is_nan:
            return "ExtendedReal(NaN)"
        return f"ExtendedReal({self._value})"
    
    def __str__(self) -> str:
        if self.is_positive_inf:
            return "+∞"
        elif self.is_negative_inf:
            return "-∞"
        elif self.is_nan:
            return "NaN"
        return str(self._value)
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, ExtendedReal):
            if self.is_nan or other.is_nan:
                return False  # NaN != NaN
            return self._type == other._type and self._value == other._value
        if isinstance(other, (int, float)):
            return self == ExtendedReal.from_float(float(other))
        return NotImplemented
    
    def __lt__(self, other: object) -> bool:
        if isinstance(other, ExtendedReal):
            if self.is_nan or other.is_nan:
                return False
            if self.is_negative_inf:
                return not other.is_negative_inf
            if self.is_positive_inf:
                return False
            if other.is_negative_inf:
                return False
            if other.is_positive_inf:
                return True
            return self._value < other._value
        if isinstance(other, (int, float)):
            return self < ExtendedReal.from_float(float(other))
        return NotImplemented
    
    def __hash__(self) -> int:
        return hash((self._value, self._type))
    
    def __neg__(self) -> ExtendedReal:
        if self.is_positive_inf:
            return NEGATIVE_INF
        if self.is_negative_inf:
            return POSITIVE_INF
        if self.is_nan:
            return NAN
        return ExtendedReal(-self._value)
    
    def __abs__(self) -> ExtendedReal:
        if self.is_nan:
            return NAN
        if self.is_infinite:
            return POSITIVE_INF
        return ExtendedReal(abs(self._value))
    
    def __add__(self, other: Union[ExtendedReal, int, float]) -> ExtendedReal:
        if isinstance(other, (int, float)):
            other = ExtendedReal.from_float(float(other))
        
        if self.is_nan or other.is_nan:
            return NAN
        
        # ∞ + (-∞) = NaN
        if (self.is_positive_inf and other.is_negative_inf) or \
           (self.is_negative_inf and other.is_positive_inf):
            return NAN
        
        if self.is_positive_inf or other.is_positive_inf:
            return POSITIVE_INF
        if self.is_negative_inf or other.is_negative_inf:
            return NEGATIVE_INF
        
        return ExtendedReal(self._value + other._value)
    
    def __radd__(self, other: Union[int, float]) -> ExtendedReal:
        return self + other
    
    def __sub__(self, other: Union[ExtendedReal, int, float]) -> ExtendedReal:
        if isinstance(other, (int, float)):
            other = ExtendedReal.from_float(float(other))
        return self + (-other)
    
    def __rsub__(self, other: Union[int, float]) -> ExtendedReal:
        return ExtendedReal.from_float(float(other)) - self
    
    def __mul__(self, other: Union[ExtendedReal, int, float]) -> ExtendedReal:
        if isinstance(other, (int, float)):
            other = ExtendedReal.from_float(float(other))
        
        if self.is_nan or other.is_nan:
            return NAN
        
        # 0 * ∞ = NaN
        if (self._value == 0 and other.is_infinite) or \
           (other._value == 0 and self.is_infinite):
            return NAN
        
        # Determine sign of result
        self_negative = self.is_negative_inf or (self.is_finite and self._value < 0)
        other_negative = other.is_negative_inf or (other.is_finite and other._value < 0)
        result_negative = self_negative != other_negative
        
        if self.is_infinite or other.is_infinite:
            return NEGATIVE_INF if result_negative else POSITIVE_INF
        
        return ExtendedReal(self._value * other._value)
    
    def __rmul__(self, other: Union[int, float]) -> ExtendedReal:
        return self * other
    
    def __truediv__(self, other: Union[ExtendedReal, int, float]) -> ExtendedReal:
        if isinstance(other, (int, float)):
            other = ExtendedReal.from_float(float(other))
        
        if self.is_nan or other.is_nan:
            return NAN
        
        # x / 0 = NaN (or ±∞, but we use NaN for safety)
        if other.is_finite and other._value == 0:
            return NAN
        
        # ∞ / ∞ = NaN
        if self.is_infinite and other.is_infinite:
            return NAN
        
        # x / ∞ = 0
        if other.is_infinite:
            return ExtendedReal(0.0)
        
        # ∞ / x
        if self.is_infinite:
            self_negative = self.is_negative_inf
            other_negative = other._value < 0
            result_negative = self_negative != other_negative
            return NEGATIVE_INF if result_negative else POSITIVE_INF
        
        return ExtendedReal(self._value / other._value)
    
    def __rtruediv__(self, other: Union[int, float]) -> ExtendedReal:
        return ExtendedReal.from_float(float(other)) / self
    
    @staticmethod
    def min(a: ExtendedReal, b: ExtendedReal) -> ExtendedReal:
        """Minimum of two extended reals."""
        if a.is_nan:
            return b
        if b.is_nan:
            return a
        return a if a < b else b
    
    @staticmethod
    def max(a: ExtendedReal, b: ExtendedReal) -> ExtendedReal:
        """Maximum of two extended reals."""
        if a.is_nan:
            return b
        if b.is_nan:
            return a
        return a if a > b else b


# Singleton instances
POSITIVE_INF = ExtendedReal(float('inf'), ExtendedRealType.POSITIVE_INF)
NEGATIVE_INF = ExtendedReal(float('-inf'), ExtendedRealType.NEGATIVE_INF)
NAN = ExtendedReal(float('nan'), ExtendedRealType.NAN)
ZERO = ExtendedReal(0.0)
ONE = ExtendedReal(1.0)
NEGATIVE_ONE = ExtendedReal(-1.0)


# =============================================================================
# Interval Domain
# =============================================================================

@dataclass(slots=True)
class Interval:
    """
    Interval abstract domain element: [lo, hi] ⊆ R.
    
    Represents a closed interval of real numbers. Supports:
    - Full arithmetic with sound overapproximation
    - Lattice operations (join, meet, widening)
    - Comparison operations
    - Conversion to barrier polynomials
    
    The interval is BOTTOM (empty) if lo > hi.
    The interval is TOP (all reals) if lo = -∞ and hi = +∞.
    
    Examples:
        >>> Interval(0, 1)
        [0, 1]
        >>> Interval(-1, 1) + Interval(2, 3)
        [1, 4]
        >>> Interval(-1, 1).excludes_zero()
        False
        >>> Interval(2, 5).excludes_zero()
        True
    
    Barrier Certificate Connection:
        For interval [a, b], the barrier polynomial is:
            B(x) = (x - a)(b - x)
        which is ≥ 0 iff x ∈ [a, b].
    """
    lo: float
    hi: float
    
    def __post_init__(self):
        # Convert to float if needed
        if isinstance(self.lo, ExtendedReal):
            self.lo = self.lo.to_float()
        if isinstance(self.hi, ExtendedReal):
            self.hi = self.hi.to_float()
    
    # =========================================================================
    # Constructors
    # =========================================================================
    
    @classmethod
    def TOP(cls) -> Interval:
        """Top element: all real numbers."""
        return cls(float('-inf'), float('inf'))
    
    @classmethod
    def BOTTOM(cls) -> Interval:
        """Bottom element: empty set."""
        return cls(float('inf'), float('-inf'))
    
    @classmethod
    def point(cls, v: float) -> Interval:
        """Singleton interval [v, v]."""
        return cls(v, v)
    
    @classmethod
    def from_bounds(cls, lo: float, hi: float) -> Interval:
        """Create interval with validation."""
        return cls(lo, hi)
    
    @classmethod
    def non_negative(cls) -> Interval:
        """Non-negative reals [0, +∞)."""
        return cls(0.0, float('inf'))
    
    @classmethod
    def positive(cls) -> Interval:
        """Positive reals (0, +∞), approximated as [ε, +∞)."""
        return cls(1e-300, float('inf'))
    
    @classmethod
    def non_positive(cls) -> Interval:
        """Non-positive reals (-∞, 0]."""
        return cls(float('-inf'), 0.0)
    
    @classmethod
    def negative(cls) -> Interval:
        """Negative reals (-∞, 0), approximated as (-∞, -ε]."""
        return cls(float('-inf'), -1e-300)
    
    @classmethod
    def unit(cls) -> Interval:
        """Unit interval [0, 1]."""
        return cls(0.0, 1.0)
    
    @classmethod
    def symmetric_unit(cls) -> Interval:
        """Symmetric unit interval [-1, 1]."""
        return cls(-1.0, 1.0)
    
    @classmethod
    def probability(cls) -> Interval:
        """Probability interval [0, 1]."""
        return cls(0.0, 1.0)
    
    @classmethod
    def angle_radians(cls) -> Interval:
        """Angle in radians [-π, π]."""
        return cls(-math.pi, math.pi)
    
    @classmethod
    def angle_degrees(cls) -> Interval:
        """Angle in degrees [-180, 180]."""
        return cls(-180.0, 180.0)
    
    # =========================================================================
    # Properties
    # =========================================================================
    
    @property
    def is_bottom(self) -> bool:
        """True if this is the empty interval."""
        return self.lo > self.hi
    
    @property
    def is_top(self) -> bool:
        """True if this is the interval of all reals."""
        return math.isinf(self.lo) and self.lo < 0 and \
               math.isinf(self.hi) and self.hi > 0
    
    @property
    def is_bounded(self) -> bool:
        """True if both bounds are finite."""
        return not math.isinf(self.lo) and not math.isinf(self.hi)
    
    @property
    def is_point(self) -> bool:
        """True if this is a singleton interval."""
        return self.lo == self.hi and not self.is_bottom
    
    @property
    def width(self) -> float:
        """Width of the interval (hi - lo)."""
        if self.is_bottom:
            return 0.0
        if math.isinf(self.lo) or math.isinf(self.hi):
            return float('inf')
        return self.hi - self.lo
    
    @property
    def midpoint(self) -> float:
        """Midpoint of the interval."""
        if self.is_bottom:
            return float('nan')
        if self.is_top:
            return 0.0
        if math.isinf(self.lo):
            return self.hi - 1.0
        if math.isinf(self.hi):
            return self.lo + 1.0
        return (self.lo + self.hi) / 2.0
    
    @property
    def radius(self) -> float:
        """Radius from midpoint to bounds."""
        return self.width / 2.0
    
    # =========================================================================
    # Zero/Sign Tests (Critical for Division Safety)
    # =========================================================================
    
    def contains_zero(self) -> bool:
        """
        Check if zero is in the interval.
        
        This is the PRIMARY check for division safety.
        If contains_zero() is True, division might fail.
        """
        if self.is_bottom:
            return False
        return self.lo <= 0.0 <= self.hi
    
    def excludes_zero(self) -> bool:
        """
        Check if zero is NOT in the interval.
        
        This PROVES division safety via barrier certificate:
            If x ∈ [a, b] and 0 ∉ [a, b], then x ≠ 0
        """
        if self.is_bottom:
            return True  # Empty set excludes everything
        return self.hi < 0.0 or self.lo > 0.0
    
    def is_strictly_positive(self) -> bool:
        """Check if all values are > 0."""
        return not self.is_bottom and self.lo > 0.0
    
    def is_strictly_negative(self) -> bool:
        """Check if all values are < 0."""
        return not self.is_bottom and self.hi < 0.0
    
    def is_non_negative(self) -> bool:
        """Check if all values are ≥ 0."""
        return not self.is_bottom and self.lo >= 0.0
    
    def is_non_positive(self) -> bool:
        """Check if all values are ≤ 0."""
        return not self.is_bottom and self.hi <= 0.0
    
    def sign(self) -> int:
        """
        Determine sign of all values in interval.
        
        Returns:
            1 if strictly positive
            -1 if strictly negative
            0 if contains zero or mixed signs
        """
        if self.is_strictly_positive():
            return 1
        if self.is_strictly_negative():
            return -1
        return 0
    
    def contains(self, value: float) -> bool:
        """Check if a value is in the interval."""
        if self.is_bottom:
            return False
        return self.lo <= value <= self.hi
    
    def contains_interval(self, other: Interval) -> bool:
        """Check if another interval is contained in this one."""
        if other.is_bottom:
            return True
        if self.is_bottom:
            return False
        return self.lo <= other.lo and other.hi <= self.hi
    
    def overlaps(self, other: Interval) -> bool:
        """Check if two intervals overlap."""
        if self.is_bottom or other.is_bottom:
            return False
        return self.lo <= other.hi and other.lo <= self.hi
    
    # =========================================================================
    # Arithmetic Operations (Sound Overapproximation)
    # =========================================================================
    
    def __add__(self, other: Union[Interval, int, float]) -> Interval:
        """
        Interval addition: [a,b] + [c,d] = [a+c, b+d]
        
        Sound: ∀x ∈ [a,b], y ∈ [c,d]: x + y ∈ [a+c, b+d]
        """
        if isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        if self.is_bottom or other.is_bottom:
            return Interval.BOTTOM()
        
        return Interval(self.lo + other.lo, self.hi + other.hi)
    
    def __radd__(self, other: Union[int, float]) -> Interval:
        return self + other
    
    def __sub__(self, other: Union[Interval, int, float]) -> Interval:
        """
        Interval subtraction: [a,b] - [c,d] = [a-d, b-c]
        
        Sound: ∀x ∈ [a,b], y ∈ [c,d]: x - y ∈ [a-d, b-c]
        """
        if isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        if self.is_bottom or other.is_bottom:
            return Interval.BOTTOM()
        
        return Interval(self.lo - other.hi, self.hi - other.lo)
    
    def __rsub__(self, other: Union[int, float]) -> Interval:
        return Interval.point(float(other)) - self
    
    def __neg__(self) -> Interval:
        """Interval negation: -[a,b] = [-b, -a]"""
        if self.is_bottom:
            return Interval.BOTTOM()
        return Interval(-self.hi, -self.lo)
    
    def __mul__(self, other: Union[Interval, int, float]) -> Interval:
        """
        Interval multiplication: [a,b] × [c,d] = [min products, max products]
        
        Sound: ∀x ∈ [a,b], y ∈ [c,d]: x × y ∈ result
        """
        if isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        if self.is_bottom or other.is_bottom:
            return Interval.BOTTOM()
        
        # Compute all four products
        products = [
            self.lo * other.lo,
            self.lo * other.hi,
            self.hi * other.lo,
            self.hi * other.hi,
        ]
        
        # Handle NaN from inf * 0
        products = [p for p in products if not math.isnan(p)]
        if not products:
            return Interval.TOP()
        
        return Interval(min(products), max(products))
    
    def __rmul__(self, other: Union[int, float]) -> Interval:
        return self * other
    
    def __truediv__(self, other: Union[Interval, int, float]) -> Interval:
        """
        Interval division with zero handling.
        
        If the divisor interval contains zero, returns TOP (could be anything).
        Otherwise, computes sound overapproximation.
        
        Division Safety:
            If other.excludes_zero(), the division is safe and we get a sound result.
            If other.contains_zero(), we return TOP (potential division by zero).
        """
        if isinstance(other, (int, float)):
            other = Interval.point(float(other))
        
        if self.is_bottom or other.is_bottom:
            return Interval.BOTTOM()
        
        # Division by interval containing zero
        if other.contains_zero():
            # Check for exact zero
            if other.lo == 0.0 and other.hi == 0.0:
                return Interval.BOTTOM()  # Division by exactly zero
            
            # Otherwise, result could be anything
            return Interval.TOP()
        
        # Safe division (0 ∉ other)
        if other.lo > 0:
            # Divisor is strictly positive
            return Interval(
                self.lo / other.hi,  # smallest / largest
                self.hi / other.lo   # largest / smallest
            )
        else:
            # Divisor is strictly negative (other.hi < 0)
            return Interval(
                self.hi / other.hi,  # largest / largest (both negative)
                self.lo / other.lo   # smallest / smallest (both negative)
            )
    
    def __rtruediv__(self, other: Union[int, float]) -> Interval:
        return Interval.point(float(other)) / self
    
    def __pow__(self, n: int) -> Interval:
        """
        Interval power: [a,b]^n
        
        Handles even/odd exponents correctly.
        """
        if self.is_bottom:
            return Interval.BOTTOM()
        
        if n == 0:
            return Interval.point(1.0)
        
        if n == 1:
            return self
        
        if n < 0:
            return Interval.point(1.0) / (self ** (-n))
        
        if n % 2 == 0:
            # Even power: always non-negative
            if self.lo >= 0:
                return Interval(self.lo ** n, self.hi ** n)
            elif self.hi <= 0:
                return Interval(self.hi ** n, self.lo ** n)
            else:
                # Contains zero
                return Interval(0.0, max(self.lo ** n, self.hi ** n))
        else:
            # Odd power: preserves sign
            return Interval(self.lo ** n, self.hi ** n)
    
    def __abs__(self) -> Interval:
        """Absolute value of interval."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        if self.lo >= 0:
            return self
        if self.hi <= 0:
            return -self
        # Contains zero
        return Interval(0.0, max(-self.lo, self.hi))
    
    # =========================================================================
    # Unary Mathematical Functions
    # =========================================================================
    
    def sqrt(self) -> Interval:
        """Square root (requires non-negative)."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        lo = max(0.0, self.lo)
        if lo > self.hi:
            return Interval.BOTTOM()  # No valid values
        
        return Interval(math.sqrt(lo), math.sqrt(self.hi))
    
    def exp(self) -> Interval:
        """Exponential function."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        if math.isinf(self.lo) and self.lo < 0:
            return Interval(0.0, math.exp(self.hi) if not math.isinf(self.hi) else float('inf'))
        if math.isinf(self.hi):
            return Interval(math.exp(self.lo), float('inf'))
        
        return Interval(math.exp(self.lo), math.exp(self.hi))
    
    def log(self) -> Interval:
        """Natural logarithm (requires positive)."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        lo = max(1e-300, self.lo)  # Avoid log(0)
        if lo > self.hi:
            return Interval.BOTTOM()
        
        return Interval(
            math.log(lo),
            math.log(self.hi) if not math.isinf(self.hi) else float('inf')
        )
    
    def sin(self) -> Interval:
        """Sine function (always returns [-1, 1] for unbounded input)."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        # For bounded intervals within one period, we could be more precise
        # For now, use sound overapproximation
        if self.width >= 2 * math.pi:
            return Interval(-1.0, 1.0)
        
        # Compute bounds (simplified)
        return Interval(-1.0, 1.0)
    
    def cos(self) -> Interval:
        """Cosine function."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        if self.width >= 2 * math.pi:
            return Interval(-1.0, 1.0)
        
        return Interval(-1.0, 1.0)
    
    def tan(self) -> Interval:
        """Tangent function."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        # Tan has asymptotes, so unless we check carefully, return TOP
        return Interval.TOP()
    
    def tanh(self) -> Interval:
        """Hyperbolic tangent (always in (-1, 1))."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        if math.isinf(self.lo) and self.lo < 0:
            lo = -1.0
        else:
            lo = math.tanh(self.lo)
        
        if math.isinf(self.hi):
            hi = 1.0
        else:
            hi = math.tanh(self.hi)
        
        return Interval(lo, hi)
    
    def sigmoid(self) -> Interval:
        """Logistic sigmoid: 1 / (1 + exp(-x))."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        # Sigmoid is monotonically increasing
        if math.isinf(self.lo) and self.lo < 0:
            lo = 0.0
        else:
            lo = 1.0 / (1.0 + math.exp(-self.lo))
        
        if math.isinf(self.hi):
            hi = 1.0
        else:
            hi = 1.0 / (1.0 + math.exp(-self.hi))
        
        return Interval(lo, hi)
    
    def relu(self) -> Interval:
        """ReLU activation: max(0, x)."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        return Interval(max(0.0, self.lo), max(0.0, self.hi))
    
    def clamp(self, min_val: float, max_val: float) -> Interval:
        """Clamp to [min_val, max_val]."""
        if self.is_bottom:
            return Interval.BOTTOM()
        
        return Interval(
            max(min_val, min(max_val, self.lo)),
            max(min_val, min(max_val, self.hi))
        )
    
    # =========================================================================
    # Lattice Operations
    # =========================================================================
    
    def join(self, other: Interval) -> Interval:
        """
        Least upper bound (⊔): smallest interval containing both.
        
        This is the union overapproximation.
        """
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))
    
    def meet(self, other: Interval) -> Interval:
        """
        Greatest lower bound (⊓): intersection of intervals.
        """
        if self.is_bottom or other.is_bottom:
            return Interval.BOTTOM()
        
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        
        if new_lo > new_hi:
            return Interval.BOTTOM()
        
        return Interval(new_lo, new_hi)
    
    def widen(self, other: Interval) -> Interval:
        """
        Widening operator for convergence.
        
        Standard widening:
            lo' = lo if other.lo >= lo else -∞
            hi' = hi if other.hi <= hi else +∞
        """
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        
        new_lo = self.lo if other.lo >= self.lo else float('-inf')
        new_hi = self.hi if other.hi <= self.hi else float('inf')
        
        return Interval(new_lo, new_hi)
    
    def narrow(self, other: Interval) -> Interval:
        """
        Narrowing operator for improved precision.
        
        Standard narrowing:
            lo' = other.lo if lo = -∞ else lo
            hi' = other.hi if hi = +∞ else hi
        """
        if self.is_bottom or other.is_bottom:
            return Interval.BOTTOM()
        
        new_lo = other.lo if math.isinf(self.lo) and self.lo < 0 else self.lo
        new_hi = other.hi if math.isinf(self.hi) and self.hi > 0 else self.hi
        
        return Interval(new_lo, new_hi)
    
    # =========================================================================
    # Comparison (Partial Order)
    # =========================================================================
    
    def __le__(self, other: Interval) -> bool:
        """
        Subset ordering: self ⊑ other iff self ⊆ other.
        """
        if self.is_bottom:
            return True
        if other.is_bottom:
            return False
        return other.lo <= self.lo and self.hi <= other.hi
    
    def __ge__(self, other: Interval) -> bool:
        return other <= self
    
    def __lt__(self, other: Interval) -> bool:
        return self <= other and not (other <= self)
    
    def __gt__(self, other: Interval) -> bool:
        return other < self
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Interval):
            return NotImplemented
        if self.is_bottom and other.is_bottom:
            return True
        return self.lo == other.lo and self.hi == other.hi
    
    def __hash__(self) -> int:
        return hash((self.lo, self.hi))
    
    # =========================================================================
    # Representation
    # =========================================================================
    
    def __repr__(self) -> str:
        if self.is_bottom:
            return "Interval(⊥)"
        if self.is_top:
            return "Interval(⊤)"
        
        lo_str = "-∞" if math.isinf(self.lo) and self.lo < 0 else f"{self.lo}"
        hi_str = "+∞" if math.isinf(self.hi) and self.hi > 0 else f"{self.hi}"
        
        return f"[{lo_str}, {hi_str}]"
    
    def __str__(self) -> str:
        return self.__repr__()
    
    # =========================================================================
    # Barrier Certificate Generation
    # =========================================================================
    
    def barrier_polynomial_coefficients(self) -> Optional[Tuple[float, float, float]]:
        """
        Get coefficients for barrier polynomial B(x) = -(x-a)(x-b) = -x² + (a+b)x - ab
        
        The polynomial B(x) ≥ 0 iff x ∈ [a, b].
        
        Returns:
            (a₂, a₁, a₀) such that B(x) = a₂x² + a₁x + a₀
            or None if interval is unbounded
        """
        if not self.is_bounded or self.is_bottom:
            return None
        
        a, b = self.lo, self.hi
        return (-1.0, a + b, -a * b)
    
    def to_sos_constraint(self, var_name: str = "x") -> str:
        """
        Generate SOS constraint string for barrier verification.
        
        Returns constraint: (x - lo) * (hi - x) >= 0
        """
        if not self.is_bounded:
            return "true"
        
        return f"({var_name} - {self.lo}) * ({self.hi} - {var_name}) >= 0"
    
    def to_smt_constraint(self, var_name: str = "x") -> str:
        """
        Generate SMT-LIB constraint for Z3/Spacer.
        """
        constraints = []
        
        if not math.isinf(self.lo):
            constraints.append(f"(>= {var_name} {self.lo})")
        if not math.isinf(self.hi):
            constraints.append(f"(<= {var_name} {self.hi})")
        
        if not constraints:
            return "true"
        if len(constraints) == 1:
            return constraints[0]
        return f"(and {' '.join(constraints)})"


# =============================================================================
# Interval Vector (for multi-dimensional analysis)
# =============================================================================

@dataclass
class IntervalVector:
    """
    Vector of intervals for multi-dimensional analysis.
    
    Represents a box (hyperrectangle) in n-dimensional space.
    """
    intervals: List[Interval]
    
    def __init__(self, intervals: Optional[List[Interval]] = None):
        self.intervals = intervals or []
    
    @classmethod
    def from_bounds(cls, bounds: List[Tuple[float, float]]) -> IntervalVector:
        """Create from list of (lo, hi) tuples."""
        return cls([Interval(lo, hi) for lo, hi in bounds])
    
    @classmethod
    def top(cls, n: int) -> IntervalVector:
        """Create n-dimensional TOP."""
        return cls([Interval.TOP() for _ in range(n)])
    
    @classmethod
    def bottom(cls, n: int) -> IntervalVector:
        """Create n-dimensional BOTTOM."""
        return cls([Interval.BOTTOM() for _ in range(n)])
    
    @property
    def ndim(self) -> int:
        return len(self.intervals)
    
    @property
    def is_bottom(self) -> bool:
        return any(i.is_bottom for i in self.intervals)
    
    @property
    def is_top(self) -> bool:
        return all(i.is_top for i in self.intervals)
    
    def __getitem__(self, idx: int) -> Interval:
        return self.intervals[idx]
    
    def __setitem__(self, idx: int, value: Interval):
        self.intervals[idx] = value
    
    def __len__(self) -> int:
        return len(self.intervals)
    
    def __iter__(self) -> Iterator[Interval]:
        return iter(self.intervals)
    
    def join(self, other: IntervalVector) -> IntervalVector:
        """Component-wise join."""
        assert len(self) == len(other)
        return IntervalVector([
            a.join(b) for a, b in zip(self.intervals, other.intervals)
        ])
    
    def meet(self, other: IntervalVector) -> IntervalVector:
        """Component-wise meet."""
        assert len(self) == len(other)
        return IntervalVector([
            a.meet(b) for a, b in zip(self.intervals, other.intervals)
        ])
    
    def widen(self, other: IntervalVector) -> IntervalVector:
        """Component-wise widening."""
        assert len(self) == len(other)
        return IntervalVector([
            a.widen(b) for a, b in zip(self.intervals, other.intervals)
        ])
    
    def __repr__(self) -> str:
        return f"IntervalVector({self.intervals})"


# =============================================================================
# Interval Matrix
# =============================================================================

@dataclass
class IntervalMatrix:
    """
    Matrix of intervals for linear transformation analysis.
    """
    rows: List[IntervalVector]
    
    def __init__(self, rows: Optional[List[IntervalVector]] = None):
        self.rows = rows or []
    
    @classmethod
    def from_intervals(cls, intervals: List[List[Interval]]) -> IntervalMatrix:
        return cls([IntervalVector(row) for row in intervals])
    
    @property
    def shape(self) -> Tuple[int, int]:
        if not self.rows:
            return (0, 0)
        return (len(self.rows), len(self.rows[0]))
    
    def __getitem__(self, idx: Tuple[int, int]) -> Interval:
        return self.rows[idx[0]][idx[1]]
    
    def matmul(self, vec: IntervalVector) -> IntervalVector:
        """Matrix-vector multiplication."""
        result = []
        for row in self.rows:
            acc = Interval.point(0.0)
            for a, b in zip(row.intervals, vec.intervals):
                acc = acc + a * b
            result.append(acc)
        return IntervalVector(result)
