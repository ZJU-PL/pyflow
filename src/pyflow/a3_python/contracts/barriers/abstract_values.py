"""
Abstract Values for Library Contract Analysis

This module provides abstract representations of Python/PyTorch values
for contract-based analysis. Key abstractions include:

- AbstractScalar: Numeric values with interval bounds
- AbstractTensor: Tensors with shape, dtype, device, and element bounds
- AbstractSequence: Lists/tuples with length and element bounds
- AbstractDict: Dictionaries with key/value abstractions

Device Compatibility Barriers:
    A critical feature for PyTorch is device compatibility checking.
    Operations on tensors require them to be on the same device.
    We track device as part of the abstract tensor state and create
    barriers when operations involve potentially incompatible devices.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import (
    Optional, Union, Tuple, List, Dict, Set, Any, 
    FrozenSet, Callable, TypeVar, Generic, Sequence
)
from enum import Enum, auto
from abc import ABC, abstractmethod
import math

from .intervals import Interval, IntervalVector, POSITIVE_INF, NEGATIVE_INF


# =============================================================================
# Device Abstraction (Critical for PyTorch)
# =============================================================================

class DeviceType(Enum):
    """PyTorch device types."""
    CPU = "cpu"
    CUDA = "cuda"
    MPS = "mps"
    XPU = "xpu"
    META = "meta"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Device:
    """
    Abstract representation of a PyTorch device.
    
    Used for device compatibility checking - operations on tensors
    require them to be on the same device.
    
    Barrier Certificate Connection:
        Device compatibility is a discrete barrier:
        B(d1, d2) = 1 if compatible(d1, d2) else 0
        Safety: B(d1, d2) = 1 for all reachable (d1, d2)
    
    Examples:
        >>> Device.cpu()
        Device(cpu)
        >>> Device.cuda(0)
        Device(cuda:0)
        >>> Device.cpu().compatible_with(Device.cuda(0))
        False
    """
    device_type: DeviceType
    index: Optional[int] = None
    
    # Special: unknown device (could be any)
    _is_unknown: bool = False
    
    # Special: any device (matches all)
    _is_any: bool = False
    
    @classmethod
    def cpu(cls) -> Device:
        """CPU device."""
        return cls(DeviceType.CPU, None)
    
    @classmethod
    def cuda(cls, index: int = 0) -> Device:
        """CUDA device with optional index."""
        return cls(DeviceType.CUDA, index)
    
    @classmethod
    def mps(cls) -> Device:
        """Apple Metal Performance Shaders device."""
        return cls(DeviceType.MPS, None)
    
    @classmethod
    def meta(cls) -> Device:
        """Meta device (shape-only tensors)."""
        return cls(DeviceType.META, None)
    
    @classmethod
    def unknown(cls) -> Device:
        """Unknown device - could be anything."""
        return cls(DeviceType.UNKNOWN, None, _is_unknown=True)
    
    @classmethod
    def any(cls) -> Device:
        """Any device - matches all devices (for contracts)."""
        return cls(DeviceType.UNKNOWN, None, _is_any=True)
    
    @classmethod
    def from_string(cls, s: str) -> Device:
        """Parse device string like 'cuda:0' or 'cpu'."""
        s = s.lower().strip()
        
        if s == "cpu":
            return cls.cpu()
        elif s.startswith("cuda"):
            if ":" in s:
                idx = int(s.split(":")[1])
                return cls.cuda(idx)
            return cls.cuda(0)
        elif s == "mps":
            return cls.mps()
        elif s == "meta":
            return cls.meta()
        else:
            return cls.unknown()
    
    @property
    def is_cpu(self) -> bool:
        return self.device_type == DeviceType.CPU
    
    @property
    def is_cuda(self) -> bool:
        return self.device_type == DeviceType.CUDA
    
    @property
    def is_known(self) -> bool:
        """True if device is definitely known."""
        return not self._is_unknown and not self._is_any
    
    def compatible_with(self, other: Device) -> bool:
        """
        Check if two devices are definitely compatible.
        
        Returns True only if we can PROVE they are compatible.
        Returns False if they might be incompatible.
        
        This is a BARRIER for device safety:
            If compatible_with returns True, operations are safe.
            If False, there's a potential device mismatch error.
        """
        # Any device matches everything (for contract purposes)
        if self._is_any or other._is_any:
            return True
        
        # Unknown devices are potentially incompatible
        if self._is_unknown or other._is_unknown:
            return False  # Conservative: might be incompatible
        
        # Same device type required
        if self.device_type != other.device_type:
            return False
        
        # For CUDA, must be same device index
        if self.device_type == DeviceType.CUDA:
            if self.index is not None and other.index is not None:
                return self.index == other.index
            # If either index is unknown, might be incompatible
            return False
        
        return True
    
    def might_be_compatible_with(self, other: Device) -> bool:
        """
        Check if devices MIGHT be compatible (less conservative).
        
        Returns True if there's any possibility they could be compatible.
        """
        if self._is_any or other._is_any:
            return True
        if self._is_unknown or other._is_unknown:
            return True  # Unknown could match anything
        
        return self.device_type == other.device_type
    
    def join(self, other: Device) -> Device:
        """
        Lattice join: least upper bound.
        
        If devices are same, return that device.
        If different or unknown, return unknown.
        """
        if self == other:
            return self
        if self._is_any:
            return other
        if other._is_any:
            return self
        return Device.unknown()
    
    def meet(self, other: Device) -> Optional[Device]:
        """
        Lattice meet: greatest lower bound.
        
        Returns None if incompatible (empty meet).
        """
        if self._is_any:
            return other
        if other._is_any:
            return self
        if self == other:
            return self
        if self._is_unknown:
            return other
        if other._is_unknown:
            return self
        # Incompatible
        return None
    
    def __str__(self) -> str:
        if self._is_any:
            return "any"
        if self._is_unknown:
            return "unknown"
        if self.index is not None:
            return f"{self.device_type.value}:{self.index}"
        return self.device_type.value
    
    def __repr__(self) -> str:
        return f"Device({self})"


# =============================================================================
# Data Type Abstraction
# =============================================================================

class DTypeCategory(Enum):
    """Categories of PyTorch dtypes."""
    FLOAT = auto()      # float16, float32, float64, bfloat16
    INT = auto()        # int8, int16, int32, int64
    UINT = auto()       # uint8
    BOOL = auto()       # bool
    COMPLEX = auto()    # complex64, complex128
    QUANTIZED = auto()  # quantized types
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class DType:
    """
    Abstract representation of a PyTorch dtype.
    
    Tracks the dtype category and specific type for:
    - Range checking (e.g., int8 is [-128, 127])
    - Type promotion rules
    - Memory layout analysis
    """
    category: DTypeCategory
    name: str
    bits: int = 32
    signed: bool = True
    
    # Standard dtypes
    @classmethod
    def float32(cls) -> DType:
        return cls(DTypeCategory.FLOAT, "float32", 32, True)
    
    @classmethod
    def float64(cls) -> DType:
        return cls(DTypeCategory.FLOAT, "float64", 64, True)
    
    @classmethod
    def float16(cls) -> DType:
        return cls(DTypeCategory.FLOAT, "float16", 16, True)
    
    @classmethod
    def bfloat16(cls) -> DType:
        return cls(DTypeCategory.FLOAT, "bfloat16", 16, True)
    
    @classmethod
    def int64(cls) -> DType:
        return cls(DTypeCategory.INT, "int64", 64, True)
    
    @classmethod
    def int32(cls) -> DType:
        return cls(DTypeCategory.INT, "int32", 32, True)
    
    @classmethod
    def int16(cls) -> DType:
        return cls(DTypeCategory.INT, "int16", 16, True)
    
    @classmethod
    def int8(cls) -> DType:
        return cls(DTypeCategory.INT, "int8", 8, True)
    
    @classmethod
    def uint8(cls) -> DType:
        return cls(DTypeCategory.UINT, "uint8", 8, False)
    
    @classmethod
    def bool_(cls) -> DType:
        return cls(DTypeCategory.BOOL, "bool", 1, False)
    
    @classmethod
    def complex64(cls) -> DType:
        return cls(DTypeCategory.COMPLEX, "complex64", 64, True)
    
    @classmethod
    def complex128(cls) -> DType:
        return cls(DTypeCategory.COMPLEX, "complex128", 128, True)
    
    @classmethod
    def unknown(cls) -> DType:
        return cls(DTypeCategory.UNKNOWN, "unknown", 0, True)
    
    @classmethod
    def from_string(cls, s: str) -> DType:
        """Parse dtype string."""
        s = s.lower().replace("torch.", "")
        dtype_map = {
            "float32": cls.float32,
            "float": cls.float32,
            "float64": cls.float64,
            "double": cls.float64,
            "float16": cls.float16,
            "half": cls.float16,
            "bfloat16": cls.bfloat16,
            "int64": cls.int64,
            "long": cls.int64,
            "int32": cls.int32,
            "int": cls.int32,
            "int16": cls.int16,
            "short": cls.int16,
            "int8": cls.int8,
            "uint8": cls.uint8,
            "bool": cls.bool_,
            "complex64": cls.complex64,
            "complex128": cls.complex128,
        }
        return dtype_map.get(s, cls.unknown)()
    
    @property
    def is_floating(self) -> bool:
        return self.category == DTypeCategory.FLOAT
    
    @property
    def is_integer(self) -> bool:
        return self.category in (DTypeCategory.INT, DTypeCategory.UINT)
    
    @property
    def is_complex(self) -> bool:
        return self.category == DTypeCategory.COMPLEX
    
    @property
    def value_range(self) -> Interval:
        """Get the range of values representable by this dtype."""
        if self.category == DTypeCategory.FLOAT:
            # Floats can represent very large values
            return Interval.TOP()
        elif self.category == DTypeCategory.INT:
            half = 2 ** (self.bits - 1)
            return Interval(-half, half - 1)
        elif self.category == DTypeCategory.UINT:
            return Interval(0, 2 ** self.bits - 1)
        elif self.category == DTypeCategory.BOOL:
            return Interval(0, 1)
        else:
            return Interval.TOP()
    
    def __str__(self) -> str:
        return self.name
    
    def __repr__(self) -> str:
        return f"DType({self.name})"


# Backward-compatible enum-like aliases used by generated Torch contracts.
DType.FLOAT16 = DType.float16()
DType.FLOAT32 = DType.float32()
DType.FLOAT64 = DType.float64()
DType.BFLOAT16 = DType.bfloat16()
DType.INT8 = DType.int8()
DType.INT16 = DType.int16()
DType.INT32 = DType.int32()
DType.INT64 = DType.int64()
DType.UINT8 = DType.uint8()
DType.BOOL = DType.bool_()
DType.COMPLEX64 = DType.complex64()
DType.COMPLEX128 = DType.complex128()
DType.UNKNOWN = DType.unknown()


# =============================================================================
# Shape Abstraction
# =============================================================================

@dataclass
class ShapeDim:
    """
    Abstract representation of a single dimension.
    
    Can be:
    - Concrete: exactly known value
    - Symbolic: represented by a symbol name
    - Bounded: known interval bounds
    - Unknown: could be any positive integer
    """
    concrete: Optional[int] = None
    symbol: Optional[str] = None
    bounds: Optional[Interval] = None
    
    @classmethod
    def exact(cls, n: int) -> ShapeDim:
        """Exact known dimension."""
        return cls(concrete=n, bounds=Interval.point(float(n)))
    
    @classmethod
    def symbolic(cls, name: str, lo: int = 0, hi: int = None) -> ShapeDim:
        """Symbolic dimension with optional bounds."""
        hi_val = float('inf') if hi is None else float(hi)
        return cls(symbol=name, bounds=Interval(float(lo), hi_val))
    
    @classmethod
    def unknown(cls, lo: int = 0) -> ShapeDim:
        """Unknown dimension with lower bound."""
        return cls(bounds=Interval(float(lo), float('inf')))
    
    @classmethod
    def between(cls, lo: int, hi: int) -> ShapeDim:
        """Dimension known to be in [lo, hi]."""
        return cls(bounds=Interval(float(lo), float(hi)))
    
    @property
    def is_concrete(self) -> bool:
        return self.concrete is not None
    
    @property
    def is_symbolic(self) -> bool:
        return self.symbol is not None
    
    @property
    def is_unknown(self) -> bool:
        return self.concrete is None and self.symbol is None
    
    @property
    def min_value(self) -> int:
        """Minimum possible value."""
        if self.concrete is not None:
            return self.concrete
        if self.bounds is not None:
            return int(self.bounds.lo)
        return 0
    
    @property
    def max_value(self) -> Optional[int]:
        """Maximum possible value, or None if unbounded."""
        if self.concrete is not None:
            return self.concrete
        if self.bounds is not None and not math.isinf(self.bounds.hi):
            return int(self.bounds.hi)
        return None
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.concrete == other
        if isinstance(other, ShapeDim):
            if self.concrete is not None and other.concrete is not None:
                return self.concrete == other.concrete
            if self.symbol is not None and other.symbol is not None:
                return self.symbol == other.symbol
            return False
        return NotImplemented
    
    def __hash__(self) -> int:
        return hash((self.concrete, self.symbol))
    
    def __str__(self) -> str:
        if self.concrete is not None:
            return str(self.concrete)
        if self.symbol is not None:
            return self.symbol
        if self.bounds is not None:
            return f"[{int(self.bounds.lo)}..{int(self.bounds.hi) if not math.isinf(self.bounds.hi) else '∞'}]"
        return "?"
    
    def __repr__(self) -> str:
        return f"ShapeDim({self})"


@dataclass
class Shape:
    """
    Abstract representation of tensor shape.
    
    Supports:
    - Fully concrete shapes: (3, 224, 224)
    - Partially symbolic: (batch, 3, height, width)
    - Unknown rank: could be any number of dimensions
    
    Shape Compatibility Barrier:
        Operations like add, mul require compatible shapes.
        We check shape compatibility as a barrier condition.
    """
    dims: Optional[List[ShapeDim]] = None
    _is_unknown_rank: bool = False
    
    @classmethod
    def concrete(cls, *dims: int) -> Shape:
        """Create shape with concrete dimensions."""
        return cls([ShapeDim.exact(d) for d in dims])
    
    @classmethod
    def from_tuple(cls, dims: Tuple[int, ...]) -> Shape:
        """Create from tuple of ints."""
        return cls([ShapeDim.exact(d) for d in dims])
    
    @classmethod
    def symbolic(cls, *names: str) -> Shape:
        """Create shape with symbolic dimensions."""
        return cls([ShapeDim.symbolic(n) for n in names])
    
    @classmethod
    def unknown(cls) -> Shape:
        """Unknown shape (rank and dims unknown)."""
        return cls(None, _is_unknown_rank=True)
    
    @classmethod
    def unknown_rank(cls) -> Shape:
        """Unknown rank shape."""
        return cls(None, _is_unknown_rank=True)
    
    @classmethod
    def scalar(cls) -> Shape:
        """Scalar (0-dimensional) shape."""
        return cls([])
    
    @classmethod
    def vector(cls, length: Union[int, ShapeDim]) -> Shape:
        """1-D vector shape."""
        if isinstance(length, int):
            length = ShapeDim.exact(length)
        return cls([length])
    
    @classmethod
    def matrix(cls, rows: Union[int, ShapeDim], cols: Union[int, ShapeDim]) -> Shape:
        """2-D matrix shape."""
        if isinstance(rows, int):
            rows = ShapeDim.exact(rows)
        if isinstance(cols, int):
            cols = ShapeDim.exact(cols)
        return cls([rows, cols])
    
    @property
    def is_known(self) -> bool:
        """True if rank is known."""
        return not self._is_unknown_rank and self.dims is not None
    
    @property
    def is_fully_concrete(self) -> bool:
        """True if all dimensions are concrete."""
        if not self.is_known:
            return False
        return all(d.is_concrete for d in self.dims)
    
    @property
    def rank(self) -> Optional[int]:
        """Number of dimensions, or None if unknown."""
        if self._is_unknown_rank or self.dims is None:
            return None
        return len(self.dims)
    
    @property
    def ndim(self) -> Optional[int]:
        """Alias for rank."""
        return self.rank
    
    def __len__(self) -> int:
        if self.dims is None:
            raise ValueError("Unknown rank shape has no length")
        return len(self.dims)
    
    def __getitem__(self, idx: int) -> ShapeDim:
        if self.dims is None:
            raise ValueError("Cannot index unknown rank shape")
        return self.dims[idx]
    
    def __iter__(self):
        if self.dims is None:
            raise ValueError("Cannot iterate unknown rank shape")
        return iter(self.dims)
    
    @property
    def numel(self) -> Optional[Interval]:
        """Total number of elements as interval."""
        if not self.is_known:
            return Interval.non_negative()
        
        result = Interval.point(1.0)
        for dim in self.dims:
            if dim.bounds is not None:
                result = result * dim.bounds
            else:
                return Interval.non_negative()
        return result
    
    def broadcast_with(self, other: Shape) -> Optional[Shape]:
        """
        Compute broadcast result shape.
        
        Returns None if shapes are not broadcastable.
        """
        if not self.is_known or not other.is_known:
            return Shape.unknown()
        
        result_dims = []
        self_dims = list(reversed(self.dims))
        other_dims = list(reversed(other.dims))
        
        for i in range(max(len(self_dims), len(other_dims))):
            d1 = self_dims[i] if i < len(self_dims) else ShapeDim.exact(1)
            d2 = other_dims[i] if i < len(other_dims) else ShapeDim.exact(1)
            
            if d1.is_concrete and d2.is_concrete:
                if d1.concrete == d2.concrete:
                    result_dims.append(d1)
                elif d1.concrete == 1:
                    result_dims.append(d2)
                elif d2.concrete == 1:
                    result_dims.append(d1)
                else:
                    return None  # Not broadcastable
            else:
                # Symbolic - assume broadcastable
                result_dims.append(ShapeDim.unknown())
        
        return Shape(list(reversed(result_dims)))
    
    def compatible_with(self, other: Shape) -> bool:
        """Check if shapes are definitely compatible for element-wise ops."""
        if not self.is_known or not other.is_known:
            return False  # Can't prove compatibility
        
        return self.broadcast_with(other) is not None
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, Shape):
            if self._is_unknown_rank or other._is_unknown_rank:
                return False
            if self.dims is None or other.dims is None:
                return False
            if len(self.dims) != len(other.dims):
                return False
            return all(d1 == d2 for d1, d2 in zip(self.dims, other.dims))
        if isinstance(other, tuple):
            return self == Shape.from_tuple(other)
        return NotImplemented
    
    def __hash__(self) -> int:
        if self.dims is None:
            return hash(None)
        return hash(tuple(self.dims))
    
    def __str__(self) -> str:
        if self._is_unknown_rank:
            return "(*,)"
        if self.dims is None:
            return "(?)"
        return f"({', '.join(str(d) for d in self.dims)})"
    
    def __repr__(self) -> str:
        return f"Shape{self}"


# =============================================================================
# Abstract Value Base
# =============================================================================

class AbstractValue(ABC):
    """
    Base class for all abstract values.
    
    Abstract values represent sets of concrete values through
    abstraction. They support:
    - Lattice operations (join, meet, widening)
    - Transformation through operations
    - Barrier certificate generation
    """
    
    @abstractmethod
    def is_bottom(self) -> bool:
        """True if this represents the empty set."""
        pass
    
    @abstractmethod
    def is_top(self) -> bool:
        """True if this represents all values."""
        pass
    
    @abstractmethod
    def join(self, other: AbstractValue) -> AbstractValue:
        """Least upper bound."""
        pass
    
    @abstractmethod
    def meet(self, other: AbstractValue) -> AbstractValue:
        """Greatest lower bound."""
        pass
    
    def widen(self, other: AbstractValue) -> AbstractValue:
        """Widening for convergence (defaults to join)."""
        return self.join(other)


# =============================================================================
# Abstract Scalar
# =============================================================================

@dataclass
class AbstractScalar(AbstractValue):
    """
    Abstract representation of a scalar value.
    
    Tracks:
    - Value interval
    - Whether it's an integer or float
    - Special properties (positive, non-zero, etc.)
    """
    interval: Interval = field(default_factory=Interval.TOP)
    is_integer: bool = False
    is_positive: bool = False
    is_non_negative: bool = False
    is_non_zero: bool = False
    
    @classmethod
    def top(cls) -> AbstractScalar:
        return cls(Interval.TOP())
    
    @classmethod
    def bottom(cls) -> AbstractScalar:
        return cls(Interval.BOTTOM())
    
    @classmethod
    def from_interval(cls, interval: Interval) -> AbstractScalar:
        return cls(
            interval=interval,
            is_positive=interval.is_strictly_positive(),
            is_non_negative=interval.is_non_negative(),
            is_non_zero=interval.excludes_zero(),
        )
    
    @classmethod
    def constant(cls, value: float) -> AbstractScalar:
        return cls.from_interval(Interval.point(value))
    
    @classmethod
    def non_negative(cls) -> AbstractScalar:
        return cls(
            interval=Interval.non_negative(),
            is_non_negative=True,
        )
    
    @classmethod
    def positive(cls) -> AbstractScalar:
        return cls(
            interval=Interval.positive(),
            is_positive=True,
            is_non_negative=True,
            is_non_zero=True,
        )
    
    def is_bottom(self) -> bool:
        return self.interval.is_bottom
    
    def is_top(self) -> bool:
        return self.interval.is_top and not any([
            self.is_positive, self.is_non_negative, self.is_non_zero
        ])
    
    def join(self, other: AbstractValue) -> AbstractScalar:
        if not isinstance(other, AbstractScalar):
            return AbstractScalar.top()
        return AbstractScalar(
            interval=self.interval.join(other.interval),
            is_integer=self.is_integer and other.is_integer,
            is_positive=self.is_positive and other.is_positive,
            is_non_negative=self.is_non_negative and other.is_non_negative,
            is_non_zero=self.is_non_zero and other.is_non_zero,
        )
    
    def meet(self, other: AbstractValue) -> AbstractScalar:
        if not isinstance(other, AbstractScalar):
            return self
        return AbstractScalar(
            interval=self.interval.meet(other.interval),
            is_integer=self.is_integer or other.is_integer,
            is_positive=self.is_positive or other.is_positive,
            is_non_negative=self.is_non_negative or other.is_non_negative,
            is_non_zero=self.is_non_zero or other.is_non_zero,
        )
    
    def excludes_zero(self) -> bool:
        """Check if value is definitely non-zero (division safe)."""
        return self.is_non_zero or self.interval.excludes_zero()
    
    def __add__(self, other: Union[AbstractScalar, float]) -> AbstractScalar:
        if isinstance(other, (int, float)):
            other = AbstractScalar.constant(float(other))
        return AbstractScalar.from_interval(self.interval + other.interval)
    
    def __sub__(self, other: Union[AbstractScalar, float]) -> AbstractScalar:
        if isinstance(other, (int, float)):
            other = AbstractScalar.constant(float(other))
        return AbstractScalar.from_interval(self.interval - other.interval)
    
    def __mul__(self, other: Union[AbstractScalar, float]) -> AbstractScalar:
        if isinstance(other, (int, float)):
            other = AbstractScalar.constant(float(other))
        return AbstractScalar.from_interval(self.interval * other.interval)
    
    def __truediv__(self, other: Union[AbstractScalar, float]) -> AbstractScalar:
        if isinstance(other, (int, float)):
            other = AbstractScalar.constant(float(other))
        return AbstractScalar.from_interval(self.interval / other.interval)
    
    def __repr__(self) -> str:
        flags = []
        if self.is_integer:
            flags.append("int")
        if self.is_positive:
            flags.append("pos")
        if self.is_non_negative:
            flags.append("≥0")
        if self.is_non_zero:
            flags.append("≠0")
        
        flag_str = f" ({', '.join(flags)})" if flags else ""
        return f"AbstractScalar({self.interval}{flag_str})"


# =============================================================================
# Abstract Tensor (Critical for PyTorch)
# =============================================================================

@dataclass
class AbstractTensor(AbstractValue):
    """
    Abstract representation of a PyTorch tensor.
    
    Tracks:
    - Shape (possibly symbolic)
    - DType
    - Device (CRITICAL for device compatibility barriers)
    - Element value bounds
    - Special properties (positive, normalized, etc.)
    
    Device Compatibility Barrier:
        The device field enables checking for device mismatches.
        Operations like `a + b` require `a.device == b.device`.
        
        Barrier condition: B(d1, d2) = (d1 == d2) ? 1 : 0
        If B(d1, d2) = 0 for any reachable (d1, d2), report bug.
    
    Example:
        >>> t1 = AbstractTensor(device=Device.cpu())
        >>> t2 = AbstractTensor(device=Device.cuda(0))
        >>> t1.device_compatible_with(t2)
        False  # Potential runtime error!
    """
    shape: Shape = field(default_factory=Shape.unknown)
    dtype: DType = field(default_factory=DType.unknown)
    device: Device = field(default_factory=Device.unknown)
    element_bounds: Interval = field(default_factory=Interval.TOP)
    
    # Special properties
    is_contiguous: bool = True
    requires_grad: bool = False
    is_leaf: bool = True
    
    # Semantic properties (from contracts)
    is_normalized: bool = False  # L2 norm = 1
    is_probability: bool = False  # Elements in [0, 1], sum to 1
    is_one_hot: bool = False  # One 1 per row, rest 0
    is_positive_definite: bool = False  # For matrices
    is_symmetric: bool = False  # For matrices
    
    @classmethod
    def top(cls) -> AbstractTensor:
        """Unknown tensor."""
        return cls()
    
    @classmethod
    def bottom(cls) -> AbstractTensor:
        """Empty/impossible tensor."""
        return cls(element_bounds=Interval.BOTTOM())
    
    @classmethod
    def with_shape(cls, *dims: int, dtype: str = "float32", device: str = "cpu") -> AbstractTensor:
        """Create tensor with known shape."""
        return cls(
            shape=Shape.concrete(*dims),
            dtype=DType.from_string(dtype),
            device=Device.from_string(device),
        )
    
    @classmethod
    def on_device(cls, device: Device) -> AbstractTensor:
        """Create tensor with known device."""
        return cls(device=device)
    
    @classmethod
    def cpu_tensor(cls) -> AbstractTensor:
        """Create CPU tensor."""
        return cls(device=Device.cpu())
    
    @classmethod
    def cuda_tensor(cls, index: int = 0) -> AbstractTensor:
        """Create CUDA tensor."""
        return cls(device=Device.cuda(index))
    
    @classmethod
    def bounded(cls, lo: float, hi: float) -> AbstractTensor:
        """Create tensor with bounded elements."""
        return cls(element_bounds=Interval(lo, hi))
    
    @classmethod
    def probability_tensor(cls) -> AbstractTensor:
        """Tensor representing probabilities [0, 1]."""
        return cls(
            element_bounds=Interval(0, 1),
            is_probability=True,
        )
    
    @classmethod
    def normalized_tensor(cls) -> AbstractTensor:
        """L2-normalized tensor (elements in [-1, 1])."""
        return cls(
            element_bounds=Interval(-1, 1),
            is_normalized=True,
        )
    
    def is_bottom(self) -> bool:
        return self.element_bounds.is_bottom
    
    def is_top(self) -> bool:
        return (
            not self.shape.is_known and
            self.dtype.category == DTypeCategory.UNKNOWN and
            self.device._is_unknown and
            self.element_bounds.is_top
        )
    
    def join(self, other: AbstractValue) -> AbstractTensor:
        if not isinstance(other, AbstractTensor):
            return AbstractTensor.top()
        
        return AbstractTensor(
            shape=self.shape if self.shape == other.shape else Shape.unknown(),
            dtype=self.dtype if self.dtype == other.dtype else DType.unknown(),
            device=self.device.join(other.device),
            element_bounds=self.element_bounds.join(other.element_bounds),
            is_contiguous=self.is_contiguous and other.is_contiguous,
            requires_grad=self.requires_grad or other.requires_grad,
            is_normalized=self.is_normalized and other.is_normalized,
            is_probability=self.is_probability and other.is_probability,
        )
    
    def meet(self, other: AbstractValue) -> AbstractTensor:
        if not isinstance(other, AbstractTensor):
            return self
        
        device_meet = self.device.meet(other.device)
        if device_meet is None:
            return AbstractTensor.bottom()  # Incompatible devices
        
        return AbstractTensor(
            shape=self.shape if self.shape.is_known else other.shape,
            dtype=self.dtype if self.dtype.category != DTypeCategory.UNKNOWN else other.dtype,
            device=device_meet,
            element_bounds=self.element_bounds.meet(other.element_bounds),
            is_contiguous=self.is_contiguous or other.is_contiguous,
            requires_grad=self.requires_grad and other.requires_grad,
            is_normalized=self.is_normalized or other.is_normalized,
            is_probability=self.is_probability or other.is_probability,
        )
    
    # =========================================================================
    # Device Compatibility Barrier
    # =========================================================================
    
    def device_compatible_with(self, other: AbstractTensor) -> bool:
        """
        Check if two tensors are definitely on the same device.
        
        This is a BARRIER CONDITION for PyTorch safety.
        
        Returns:
            True if PROVEN compatible (safe to operate)
            False if POSSIBLY incompatible (potential runtime error)
        
        Example:
            >>> cpu_t = AbstractTensor(device=Device.cpu())
            >>> cuda_t = AbstractTensor(device=Device.cuda(0))
            >>> cpu_t.device_compatible_with(cuda_t)
            False  # BARRIER VIOLATION - report as potential bug
        """
        return self.device.compatible_with(other.device)
    
    def might_be_device_compatible(self, other: AbstractTensor) -> bool:
        """
        Check if devices MIGHT be compatible.
        
        Less conservative - returns True if there's any possibility.
        """
        return self.device.might_be_compatible_with(other.device)
    
    def check_device_compatibility(self, other: AbstractTensor) -> Tuple[bool, Optional[str]]:
        """
        Check device compatibility and return error message if incompatible.
        
        Returns:
            (is_safe, error_message)
            is_safe: True if definitely compatible
            error_message: Description of the device mismatch, or None
        """
        if self.device_compatible_with(other):
            return (True, None)
        
        # Construct error message
        self_dev = str(self.device)
        other_dev = str(other.device)
        
        if self.device.is_known and other.device.is_known:
            return (False, f"Device mismatch: tensor on {self_dev} cannot operate with tensor on {other_dev}")
        elif self.device.is_known:
            return (False, f"Tensor on {self_dev} may be incompatible with tensor on unknown device")
        elif other.device.is_known:
            return (False, f"Tensor on unknown device may be incompatible with tensor on {other_dev}")
        else:
            return (False, f"Both tensors have unknown devices - cannot verify compatibility")
    
    # =========================================================================
    # Shape Compatibility
    # =========================================================================
    
    def shape_compatible_with(self, other: AbstractTensor) -> bool:
        """Check if shapes are broadcast-compatible."""
        return self.shape.compatible_with(other.shape)
    
    def broadcast_shape(self, other: AbstractTensor) -> Optional[Shape]:
        """Compute broadcast result shape."""
        return self.shape.broadcast_with(other.shape)
    
    # =========================================================================
    # Element Bounds
    # =========================================================================
    
    def elements_exclude_zero(self) -> bool:
        """Check if all elements are definitely non-zero."""
        return self.element_bounds.excludes_zero()
    
    def elements_non_negative(self) -> bool:
        """Check if all elements are definitely ≥ 0."""
        return self.element_bounds.is_non_negative()
    
    def elements_in_range(self, lo: float, hi: float) -> bool:
        """Check if all elements are in [lo, hi]."""
        return self.element_bounds.lo >= lo and self.element_bounds.hi <= hi
    
    # =========================================================================
    # With Methods (Functional Updates)
    # =========================================================================
    
    def with_device(self, device: Device) -> AbstractTensor:
        """Return copy with updated device."""
        return AbstractTensor(
            shape=self.shape,
            dtype=self.dtype,
            device=device,
            element_bounds=self.element_bounds,
            is_contiguous=self.is_contiguous,
            requires_grad=self.requires_grad,
            is_normalized=self.is_normalized,
            is_probability=self.is_probability,
        )
    
    def with_shape(self, shape: Shape) -> AbstractTensor:
        """Return copy with updated shape."""
        return AbstractTensor(
            shape=shape,
            dtype=self.dtype,
            device=self.device,
            element_bounds=self.element_bounds,
            is_contiguous=True,  # Shape change may affect contiguity
            requires_grad=self.requires_grad,
            is_normalized=False,  # Shape change invalidates normalization
            is_probability=False,
        )
    
    def with_element_bounds(self, bounds: Interval) -> AbstractTensor:
        """Return copy with updated element bounds."""
        return AbstractTensor(
            shape=self.shape,
            dtype=self.dtype,
            device=self.device,
            element_bounds=bounds,
            is_contiguous=self.is_contiguous,
            requires_grad=self.requires_grad,
            is_normalized=self.is_normalized if bounds.lo >= -1 and bounds.hi <= 1 else False,
            is_probability=self.is_probability if bounds.lo >= 0 and bounds.hi <= 1 else False,
        )
    
    def to_device(self, device: Device) -> AbstractTensor:
        """
        Model tensor.to(device) operation.
        
        After this, the tensor is on the target device.
        """
        return self.with_device(device)
    
    def cpu(self) -> AbstractTensor:
        """Model tensor.cpu()."""
        return self.to_device(Device.cpu())
    
    def cuda(self, index: int = 0) -> AbstractTensor:
        """Model tensor.cuda()."""
        return self.to_device(Device.cuda(index))
    
    def __repr__(self) -> str:
        parts = [f"shape={self.shape}"]
        if self.dtype.category != DTypeCategory.UNKNOWN:
            parts.append(f"dtype={self.dtype}")
        parts.append(f"device={self.device}")
        if not self.element_bounds.is_top:
            parts.append(f"elements={self.element_bounds}")
        if self.is_normalized:
            parts.append("normalized")
        if self.is_probability:
            parts.append("probability")
        
        return f"AbstractTensor({', '.join(parts)})"


# =============================================================================
# Abstract Sequence
# =============================================================================

@dataclass
class AbstractSequence(AbstractValue):
    """
    Abstract representation of a sequence (list, tuple).
    
    Tracks:
    - Length bounds
    - Element type
    - Element value bounds
    """
    length: Interval = field(default_factory=Interval.non_negative)
    element_type: Optional[type] = None
    element_bounds: Optional[Interval] = None
    
    @classmethod
    def top(cls) -> AbstractSequence:
        return cls()
    
    @classmethod
    def bottom(cls) -> AbstractSequence:
        return cls(length=Interval.BOTTOM())
    
    @classmethod
    def of_length(cls, n: int) -> AbstractSequence:
        """Sequence of exact length."""
        return cls(length=Interval.point(float(n)))
    
    @classmethod
    def non_empty(cls) -> AbstractSequence:
        """Non-empty sequence (length ≥ 1)."""
        return cls(length=Interval(1, float('inf')))
    
    @classmethod
    def empty(cls) -> AbstractSequence:
        """Empty sequence."""
        return cls(length=Interval.point(0))
    
    def is_bottom(self) -> bool:
        return self.length.is_bottom
    
    def is_top(self) -> bool:
        return self.length.is_top and self.element_type is None
    
    def join(self, other: AbstractValue) -> AbstractSequence:
        if not isinstance(other, AbstractSequence):
            return AbstractSequence.top()
        return AbstractSequence(
            length=self.length.join(other.length),
            element_type=self.element_type if self.element_type == other.element_type else None,
            element_bounds=self.element_bounds.join(other.element_bounds) if self.element_bounds and other.element_bounds else None,
        )
    
    def meet(self, other: AbstractValue) -> AbstractSequence:
        if not isinstance(other, AbstractSequence):
            return self
        return AbstractSequence(
            length=self.length.meet(other.length),
            element_type=self.element_type or other.element_type,
            element_bounds=self.element_bounds.meet(other.element_bounds) if self.element_bounds and other.element_bounds else (self.element_bounds or other.element_bounds),
        )
    
    def is_definitely_non_empty(self) -> bool:
        """Check if sequence is definitely non-empty."""
        return self.length.lo >= 1
    
    def might_be_empty(self) -> bool:
        """Check if sequence might be empty."""
        return self.length.contains(0)
    
    def __repr__(self) -> str:
        parts = [f"length={self.length}"]
        if self.element_type:
            parts.append(f"element_type={self.element_type.__name__}")
        if self.element_bounds:
            parts.append(f"element_bounds={self.element_bounds}")
        return f"AbstractSequence({', '.join(parts)})"


# =============================================================================
# Abstract Dict
# =============================================================================

@dataclass
class AbstractDict(AbstractValue):
    """
    Abstract representation of a dictionary.
    """
    known_keys: FrozenSet[str] = field(default_factory=frozenset)
    size: Interval = field(default_factory=Interval.non_negative)
    may_have_unknown_keys: bool = True
    
    @classmethod
    def top(cls) -> AbstractDict:
        return cls()
    
    @classmethod
    def bottom(cls) -> AbstractDict:
        return cls(size=Interval.BOTTOM())
    
    @classmethod
    def with_keys(cls, *keys: str) -> AbstractDict:
        return cls(
            known_keys=frozenset(keys),
            size=Interval(len(keys), float('inf')),
        )
    
    @classmethod
    def exact(cls, *keys: str) -> AbstractDict:
        return cls(
            known_keys=frozenset(keys),
            size=Interval.point(len(keys)),
            may_have_unknown_keys=False,
        )
    
    def is_bottom(self) -> bool:
        return self.size.is_bottom
    
    def is_top(self) -> bool:
        return len(self.known_keys) == 0 and self.size.is_top and self.may_have_unknown_keys
    
    def join(self, other: AbstractValue) -> AbstractDict:
        if not isinstance(other, AbstractDict):
            return AbstractDict.top()
        return AbstractDict(
            known_keys=self.known_keys & other.known_keys,
            size=self.size.join(other.size),
            may_have_unknown_keys=self.may_have_unknown_keys or other.may_have_unknown_keys,
        )
    
    def meet(self, other: AbstractValue) -> AbstractDict:
        if not isinstance(other, AbstractDict):
            return self
        return AbstractDict(
            known_keys=self.known_keys | other.known_keys,
            size=self.size.meet(other.size),
            may_have_unknown_keys=self.may_have_unknown_keys and other.may_have_unknown_keys,
        )
    
    def definitely_has_key(self, key: str) -> bool:
        """Check if key is definitely present."""
        return key in self.known_keys
    
    def might_have_key(self, key: str) -> bool:
        """Check if key might be present."""
        return key in self.known_keys or self.may_have_unknown_keys
    
    def __repr__(self) -> str:
        if self.is_top:
            return "AbstractDict(⊤)"
        if self.is_bottom:
            return "AbstractDict(⊥)"
        
        parts = []
        if self.known_keys:
            parts.append(f"keys={{{', '.join(sorted(self.known_keys)[:5])}{'...' if len(self.known_keys) > 5 else ''}}}")
        parts.append(f"size={self.size}")
        if not self.may_have_unknown_keys:
            parts.append("exact")
        
        return f"AbstractDict({', '.join(parts)})"
