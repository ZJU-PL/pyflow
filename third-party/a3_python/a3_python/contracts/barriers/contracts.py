"""
Library Contracts

This module defines the contract specification for library functions,
enabling semantic analysis through deferred barrier propagation.

A LibraryContract specifies:
- Return value interval (e.g., cosine_similarity → [-1, 1])
- Preconditions on arguments
- Postconditions on return values
- Side effects (e.g., modifies in-place)
- Device propagation (PyTorch)
- Shape transformations (PyTorch)

Usage:
    contract = FunctionContract(
        name="cosine_similarity",
        module="torch.nn.functional",
        return_interval=Interval(-1, 1),
    )
    
    # When analyzing: similarity = F.cosine_similarity(a, b)
    barrier = contract.create_barrier("similarity")
    # barrier.current_interval = [-1, 1]
    
    # Later: diff = similarity - 3
    barrier = barrier.subtract(3)
    # barrier.current_interval = [-4, -2]
    # barrier.proves_nonzero() = True → division is safe!
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import (
    Optional, Union, List, Dict, Any, Tuple,
    Callable, Set, FrozenSet, Type, TypeVar
)
from enum import Enum, auto
from abc import ABC, abstractmethod
import math

from .intervals import Interval
from .abstract_values import (
    AbstractValue, AbstractTensor, AbstractScalar,
    AbstractSequence, AbstractDict, Shape, DType, Device
)
from .deferred import (
    DeferredBarrier, DeferredConstraint, ConstraintKind,
    BarrierStrength, DeviceBarrier
)


# =============================================================================
# Contract Types
# =============================================================================

class ContractKind(Enum):
    """Kinds of contracts."""
    FUNCTION = auto()    # Standalone function
    METHOD = auto()      # Instance method
    PROPERTY = auto()    # Property accessor
    MODULE = auto()      # nn.Module subclass
    CLASS = auto()       # Class constructor


class SideEffect(Enum):
    """Side effects a function may have."""
    NONE = auto()           # Pure function
    MODIFIES_SELF = auto()  # Modifies self in-place
    MODIFIES_ARG = auto()   # Modifies an argument
    ALLOCATES = auto()      # Allocates memory
    READS_GLOBAL = auto()   # Reads global state
    WRITES_GLOBAL = auto()  # Writes global state
    IO = auto()             # Performs I/O
    RANDOM = auto()         # Uses random numbers


# =============================================================================
# Preconditions and Postconditions
# =============================================================================

@dataclass
class Precondition:
    """
    A precondition on function arguments.
    
    Examples:
        - dim must be < input.ndim
        - input must be non-empty
        - alpha must be positive
    """
    parameter: str
    condition: str
    interval: Optional[Interval] = None
    
    # For checking
    check_fn: Optional[Callable[[Any], bool]] = None
    
    @classmethod
    def positive(cls, param: str) -> Precondition:
        return cls(param, f"{param} > 0", Interval.positive())
    
    @classmethod
    def non_negative(cls, param: str) -> Precondition:
        return cls(param, f"{param} >= 0", Interval.non_negative())
    
    @classmethod
    def non_zero(cls, param: str) -> Precondition:
        return cls(param, f"{param} != 0")
    
    @classmethod
    def in_range(cls, param: str, lo: float, hi: float) -> Precondition:
        return cls(param, f"{param} in [{lo}, {hi}]", Interval(lo, hi))
    
    @classmethod
    def non_empty(cls, param: str) -> Precondition:
        return cls(param, f"len({param}) > 0")
    
    def __repr__(self) -> str:
        return f"Precondition({self.condition})"


@dataclass
class Postcondition:
    """
    A postcondition on function return value.
    """
    condition: str
    interval: Optional[Interval] = None
    creates_barrier: bool = True
    
    @classmethod
    def in_interval(cls, lo: float, hi: float) -> Postcondition:
        return cls(f"result in [{lo}, {hi}]", Interval(lo, hi))
    
    @classmethod
    def positive(cls) -> Postcondition:
        return cls("result > 0", Interval.positive())
    
    @classmethod
    def non_negative(cls) -> Postcondition:
        return cls("result >= 0", Interval.non_negative())
    
    @classmethod
    def non_zero(cls) -> Postcondition:
        return cls("result != 0")
    
    @classmethod
    def unit(cls) -> Postcondition:
        return cls("result in [0, 1]", Interval.unit())
    
    @classmethod
    def symmetric_unit(cls) -> Postcondition:
        return cls("result in [-1, 1]", Interval.symmetric_unit())
    
    def __repr__(self) -> str:
        return f"Postcondition({self.condition})"


@dataclass
class Invariant:
    """
    An invariant relating inputs to outputs.
    
    Examples:
        - output.shape[0] == input.shape[0]
        - output.device == input.device
    """
    condition: str
    preserves_device: bool = False
    preserves_dtype: bool = False
    preserves_shape: bool = False
    
    @classmethod
    def same_device(cls) -> Invariant:
        return cls("output.device == input.device", preserves_device=True)
    
    @classmethod
    def same_dtype(cls) -> Invariant:
        return cls("output.dtype == input.dtype", preserves_dtype=True)
    
    @classmethod
    def same_shape(cls) -> Invariant:
        return cls("output.shape == input.shape", preserves_shape=True)
    
    def __repr__(self) -> str:
        return f"Invariant({self.condition})"


# =============================================================================
# Base Contract
# =============================================================================

@dataclass
class LibraryContract(ABC):
    """
    Base class for library function contracts.
    
    A contract specifies the semantic behavior of a library function,
    enabling:
    - Return value interval tracking
    - Deferred barrier creation
    - Device/shape propagation
    - Precondition verification
    """
    
    name: str
    module: str = ""
    kind: ContractKind = ContractKind.FUNCTION
    
    # Documentation
    description: str = ""
    
    # Return value specification
    return_interval: Optional[Interval] = None
    return_interval_fn: Optional[Callable[..., Interval]] = None
    
    # Guarantees
    guarantees_positive: bool = False
    guarantees_non_negative: bool = False
    guarantees_non_zero: bool = False
    guarantees_finite: bool = False
    
    # Preconditions and postconditions
    preconditions: List[Precondition] = field(default_factory=list)
    postconditions: List[Postcondition] = field(default_factory=list)
    invariants: List[Invariant] = field(default_factory=list)
    
    # Side effects
    side_effects: Set[SideEffect] = field(default_factory=lambda: {SideEffect.NONE})
    
    # Device behavior (PyTorch)
    preserves_device: bool = True  # Output on same device as input
    device_from_arg: Optional[str] = None  # Which arg determines device
    
    # Shape behavior (PyTorch)
    preserves_shape: bool = False
    output_shape_fn: Optional[Callable[..., Shape]] = None
    
    # DType behavior
    preserves_dtype: bool = True
    output_dtype_fn: Optional[Callable[..., DType]] = None
    
    @property
    def full_name(self) -> str:
        """Full qualified name: module.name"""
        if self.module:
            return f"{self.module}.{self.name}"
        return self.name
    
    def get_return_interval(self, args: List[Any] = None, 
                           kwargs: Dict[str, Any] = None) -> Interval:
        """
        Get the return value interval.
        
        May depend on arguments for some functions (e.g., clamp).
        """
        if self.return_interval_fn and (args or kwargs):
            try:
                return self.return_interval_fn(*(args or []), **(kwargs or {}))
            except:
                pass
        
        if self.return_interval:
            return self.return_interval
        
        # Derive from guarantees
        if self.guarantees_positive:
            return Interval.positive()
        if self.guarantees_non_negative:
            return Interval.non_negative()
        
        return Interval.TOP()
    
    def creates_barrier(self) -> bool:
        """Check if this contract creates a useful barrier."""
        return (
            self.return_interval is not None or
            self.return_interval_fn is not None or
            self.guarantees_positive or
            self.guarantees_non_negative or
            self.guarantees_non_zero or
            len(self.postconditions) > 0
        )
    
    def create_barrier(self, variable: str, args: List[Any] = None,
                       kwargs: Dict[str, Any] = None) -> DeferredBarrier:
        """
        Create a deferred barrier for a call to this function.
        
        Args:
            variable: Name of the variable receiving the result
            args: Positional arguments to the call
            kwargs: Keyword arguments to the call
            
        Returns:
            DeferredBarrier tracking the return value constraint
        """
        interval = self.get_return_interval(args, kwargs)
        
        return DeferredBarrier(
            variable=variable,
            source_interval=interval,
            current_interval=interval,
            source_contract=self.full_name,
            source_function=self.name,
            source_module=self.module,
            strength=BarrierStrength.CONTRACT,
        )
    
    def get_output_device(self, input_tensors: List[AbstractTensor]) -> Device:
        """
        Determine output device from inputs.
        
        For most PyTorch operations, output is on same device as first input.
        """
        if self.device_from_arg is not None and input_tensors:
            # Use specific argument's device
            return input_tensors[0].device
        
        if self.preserves_device and input_tensors:
            return input_tensors[0].device
        
        return Device.unknown()
    
    def get_output_shape(self, input_shapes: List[Shape], 
                         args: List[Any] = None) -> Shape:
        """Determine output shape from inputs."""
        if self.output_shape_fn:
            try:
                return self.output_shape_fn(input_shapes, args)
            except:
                pass
        
        if self.preserves_shape and input_shapes:
            return input_shapes[0]
        
        return Shape.unknown()
    
    def check_device_compatibility(self, 
                                    tensors: List[AbstractTensor]) -> Tuple[bool, Optional[str]]:
        """
        Check if all input tensors are on compatible devices.
        
        This is a PyTorch-specific barrier check.
        
        Returns:
            (is_safe, error_message)
        """
        if len(tensors) < 2:
            return (True, None)
        
        first = tensors[0]
        for i, tensor in enumerate(tensors[1:], 2):
            is_safe, error = first.check_device_compatibility(tensor)
            if not is_safe:
                return (False, f"In {self.name}: argument 1 and {i} have incompatible devices: {error}")
        
        return (True, None)
    
    def check_preconditions(self, args: List[Any], 
                            kwargs: Dict[str, Any]) -> List[str]:
        """
        Check preconditions against arguments.
        
        Returns list of violated precondition descriptions.
        """
        violations = []
        # TODO: Implement precondition checking
        return violations
    
    def to_ice_samples(self, var: str) -> Dict[str, List[Dict[str, float]]]:
        """Generate ICE samples for learning."""
        interval = self.get_return_interval()
        barrier = DeferredBarrier.from_interval(var, interval)
        return barrier.to_ice_samples(var)
    
    def to_smt_constraint(self, var: str) -> str:
        """Generate SMT constraint."""
        interval = self.get_return_interval()
        return interval.to_smt_constraint(var)
    
    def __repr__(self) -> str:
        parts = [f"{self.full_name}"]
        if self.return_interval:
            parts.append(f"→ {self.return_interval}")
        if self.guarantees_positive:
            parts.append("(positive)")
        if self.guarantees_non_negative:
            parts.append("(non-negative)")
        return f"Contract({', '.join(parts)})"


# =============================================================================
# Function Contract
# =============================================================================

@dataclass
class FunctionContract(LibraryContract):
    """Contract for a standalone function."""
    
    kind: ContractKind = field(default=ContractKind.FUNCTION)
    
    # Parameter information
    parameters: List[str] = field(default_factory=list)
    parameter_types: Dict[str, type] = field(default_factory=dict)

    # Torch contract compatibility fields
    requires_same_device: bool = False
    qualname: str = ""
    param_names: List[str] = field(default_factory=list)
    param_intervals: Dict[str, Interval] = field(default_factory=dict)
    may_raise: List[str] = field(default_factory=list)
    docstring: str = ""
    return_dtype: Optional[Any] = None
    modifies_input: bool = False
    return_type: Optional[str] = None
    
    # Variadic
    accepts_varargs: bool = False
    accepts_kwargs: bool = False


# =============================================================================
# Method Contract  
# =============================================================================

@dataclass
class MethodContract(LibraryContract):
    """Contract for an instance method."""
    
    kind: ContractKind = field(default=ContractKind.METHOD)
    
    # Class this method belongs to
    class_name: str = ""
    
    # Self type
    self_type: Optional[type] = None
    
    # Modifies self?
    modifies_self: bool = False
    
    # Returns self?
    returns_self: bool = False

    # Torch contract compatibility fields
    requires_same_device: bool = False
    qualname: str = ""
    param_names: List[str] = field(default_factory=list)
    param_intervals: Dict[str, Interval] = field(default_factory=dict)
    may_raise: List[str] = field(default_factory=list)
    docstring: str = ""
    modifies_input: bool = False
    return_type: Optional[str] = None


# =============================================================================
# Property Contract
# =============================================================================

@dataclass
class PropertyContract(LibraryContract):
    """Contract for a property accessor."""
    
    kind: ContractKind = field(default=ContractKind.PROPERTY)
    
    # Class this property belongs to
    class_name: str = ""
    
    # Is settable?
    is_settable: bool = False
    
    # Always returns same value?
    is_constant: bool = False

    # Torch contract compatibility fields
    return_type: Optional[str] = None
    qualname: str = ""
    getter_preconditions: List[Precondition] = field(default_factory=list)
    getter_postconditions: List[Postcondition] = field(default_factory=list)
    setter_preconditions: List[Precondition] = field(default_factory=list)
    setter_postconditions: List[Postcondition] = field(default_factory=list)
    docstring: str = ""


# =============================================================================
# Module Contract (torch.nn.Module subclasses)
# =============================================================================

@dataclass
class ModuleContract(LibraryContract):
    """Contract for a torch.nn.Module subclass."""
    
    kind: ContractKind = field(default=ContractKind.MODULE)
    
    # Forward pass contract
    forward_contract: Optional[FunctionContract] = None
    
    # Learnable parameters
    parameters: List[str] = field(default_factory=list)
    
    # Buffers
    buffers: List[str] = field(default_factory=list)
    
    # Sub-modules
    submodules: List[str] = field(default_factory=list)
    
    # Training vs eval behavior differs?
    training_sensitive: bool = False

    # Torch contract compatibility fields
    forward_requires_same_device: bool = False
    forward_preserves_device: bool = False
    forward_return_interval: Optional[Interval] = None
    forward_preserves_shape: bool = False
    forward_preserves_dtype: bool = False
    forward_guarantees_non_negative: bool = False
    forward_guarantees_positive: bool = False
    qualname: str = ""
    init_param_names: List[str] = field(default_factory=list)
    init_param_intervals: Dict[str, Interval] = field(default_factory=dict)
    state_invariants: List[str] = field(default_factory=list)
    docstring: str = ""


# =============================================================================
# Contract Registry
# =============================================================================

class ContractRegistry:
    """
    Registry of library contracts.
    
    Provides lookup by:
    - Full name: "torch.nn.functional.cosine_similarity"
    - Module + name: ("torch.nn.functional", "cosine_similarity")
    - Just name: "cosine_similarity" (if unambiguous)
    
    Usage:
        registry = ContractRegistry()
        registry.register(contract)
        
        contract = registry.get("torch.nn.functional", "cosine_similarity")
    """
    
    def __init__(self):
        # Main storage: full_name -> contract
        self._contracts: Dict[str, LibraryContract] = {}
        
        # Index by module
        self._by_module: Dict[str, Dict[str, LibraryContract]] = {}
        
        # Index by name (for unqualified lookup)
        self._by_name: Dict[str, List[LibraryContract]] = {}
        
        # Statistics
        self._stats = {
            "total": 0,
            "with_interval": 0,
            "with_device": 0,
            "with_shape": 0,
        }
    
    def register(self, contract: LibraryContract) -> None:
        """Register a contract."""
        full_name = contract.full_name
        
        # Store by full name
        self._contracts[full_name] = contract
        
        # Index by module
        if contract.module not in self._by_module:
            self._by_module[contract.module] = {}
        self._by_module[contract.module][contract.name] = contract
        
        # Index by name
        if contract.name not in self._by_name:
            self._by_name[contract.name] = []
        self._by_name[contract.name].append(contract)
        
        # Update stats
        self._stats["total"] += 1
        if contract.return_interval or contract.return_interval_fn:
            self._stats["with_interval"] += 1
        if contract.preserves_device:
            self._stats["with_device"] += 1
        if contract.preserves_shape or contract.output_shape_fn:
            self._stats["with_shape"] += 1
    
    def get(self, module: str, name: str) -> Optional[LibraryContract]:
        """Get contract by module and name."""
        if module in self._by_module:
            return self._by_module[module].get(name)
        return None
    
    def get_by_full_name(self, full_name: str) -> Optional[LibraryContract]:
        """Get contract by full qualified name."""
        return self._contracts.get(full_name)
    
    def get_by_name(self, name: str) -> Optional[LibraryContract]:
        """
        Get contract by name alone.
        
        Returns None if ambiguous (multiple contracts with same name).
        """
        contracts = self._by_name.get(name, [])
        if len(contracts) == 1:
            return contracts[0]
        return None
    
    def get_all_by_name(self, name: str) -> List[LibraryContract]:
        """Get all contracts with given name."""
        return self._by_name.get(name, [])
    
    def get_module_contracts(self, module: str) -> Dict[str, LibraryContract]:
        """Get all contracts for a module."""
        return self._by_module.get(module, {})
    
    def has(self, module: str, name: str) -> bool:
        """Check if contract exists."""
        return self.get(module, name) is not None
    
    def __contains__(self, key: Union[str, Tuple[str, str]]) -> bool:
        if isinstance(key, tuple):
            module, name = key
            return self.has(module, name)
        return key in self._contracts
    
    def __len__(self) -> int:
        return len(self._contracts)
    
    def __iter__(self):
        return iter(self._contracts.values())
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get registry statistics."""
        return self._stats.copy()
    
    def modules(self) -> List[str]:
        """List all registered modules."""
        return list(self._by_module.keys())
    
    def find(self, pattern: str) -> List[LibraryContract]:
        """Find contracts matching a pattern (simple glob)."""
        import fnmatch
        return [c for c in self._contracts.values() 
                if fnmatch.fnmatch(c.full_name, pattern)]
    
    def __repr__(self) -> str:
        return f"ContractRegistry({len(self)} contracts, {len(self._by_module)} modules)"


# =============================================================================
# Contract Builder (Fluent API)
# =============================================================================

class ContractBuilder:
    """
    Fluent builder for creating contracts.
    
    Usage:
        contract = (ContractBuilder("cosine_similarity", "torch.nn.functional")
            .returns_interval(-1, 1)
            .preserves_device()
            .with_description("Cosine similarity between vectors")
            .build())
    """
    
    def __init__(self, name: str, module: str):
        self.name = name
        self.module = module
        self._kind = ContractKind.FUNCTION
        self._description = ""
        self._return_interval: Optional[Interval] = None
        self._return_interval_fn: Optional[Callable] = None
        self._guarantees_positive = False
        self._guarantees_non_negative = False
        self._guarantees_non_zero = False
        self._guarantees_finite = False
        self._preconditions: List[Precondition] = []
        self._postconditions: List[Postcondition] = []
        self._invariants: List[Invariant] = []
        self._side_effects: Set[SideEffect] = {SideEffect.NONE}
        self._preserves_device = True
        self._preserves_shape = False
        self._preserves_dtype = True
        self._device_from_arg: Optional[str] = None
        self._output_shape_fn: Optional[Callable] = None
        self._output_dtype_fn: Optional[Callable] = None
        self._parameters: List[str] = []
        self._class_name = ""
        self._modifies_self = False
        self._returns_self = False
    
    def as_method(self, class_name: str) -> ContractBuilder:
        """Mark as a method of a class."""
        self._kind = ContractKind.METHOD
        self._class_name = class_name
        return self
    
    def as_property(self, class_name: str) -> ContractBuilder:
        """Mark as a property of a class."""
        self._kind = ContractKind.PROPERTY
        self._class_name = class_name
        return self
    
    def as_module(self) -> ContractBuilder:
        """Mark as a nn.Module subclass."""
        self._kind = ContractKind.MODULE
        return self
    
    def with_description(self, desc: str) -> ContractBuilder:
        """Set description."""
        self._description = desc
        return self
    
    def returns_interval(self, lo: float, hi: float) -> ContractBuilder:
        """Set return value interval."""
        self._return_interval = Interval(lo, hi)
        return self
    
    def returns_interval_fn(self, fn: Callable[..., Interval]) -> ContractBuilder:
        """Set return interval function."""
        self._return_interval_fn = fn
        return self
    
    def returns_positive(self) -> ContractBuilder:
        """Mark return as positive."""
        self._guarantees_positive = True
        self._guarantees_non_negative = True
        self._guarantees_non_zero = True
        return self
    
    def returns_non_negative(self) -> ContractBuilder:
        """Mark return as non-negative."""
        self._guarantees_non_negative = True
        return self
    
    def returns_non_zero(self) -> ContractBuilder:
        """Mark return as non-zero."""
        self._guarantees_non_zero = True
        return self
    
    def returns_finite(self) -> ContractBuilder:
        """Mark return as finite."""
        self._guarantees_finite = True
        return self
    
    def returns_probability(self) -> ContractBuilder:
        """Return is in [0, 1]."""
        self._return_interval = Interval(0, 1)
        return self
    
    def returns_symmetric_unit(self) -> ContractBuilder:
        """Return is in [-1, 1]."""
        self._return_interval = Interval(-1, 1)
        return self
    
    def precondition(self, param: str, condition: str, 
                    interval: Interval = None) -> ContractBuilder:
        """Add a precondition."""
        self._preconditions.append(Precondition(param, condition, interval))
        return self
    
    def requires_positive(self, param: str) -> ContractBuilder:
        """Require parameter to be positive."""
        self._preconditions.append(Precondition.positive(param))
        return self
    
    def requires_non_negative(self, param: str) -> ContractBuilder:
        """Require parameter to be non-negative."""
        self._preconditions.append(Precondition.non_negative(param))
        return self
    
    def requires_non_empty(self, param: str) -> ContractBuilder:
        """Require parameter to be non-empty."""
        self._preconditions.append(Precondition.non_empty(param))
        return self
    
    def postcondition(self, condition: str, 
                     interval: Interval = None) -> ContractBuilder:
        """Add a postcondition."""
        self._postconditions.append(Postcondition(condition, interval))
        return self
    
    def invariant(self, condition: str) -> ContractBuilder:
        """Add an invariant."""
        self._invariants.append(Invariant(condition))
        return self
    
    def side_effect(self, effect: SideEffect) -> ContractBuilder:
        """Add a side effect."""
        self._side_effects.discard(SideEffect.NONE)
        self._side_effects.add(effect)
        return self
    
    def pure(self) -> ContractBuilder:
        """Mark as pure (no side effects)."""
        self._side_effects = {SideEffect.NONE}
        return self
    
    def modifies_self(self) -> ContractBuilder:
        """Mark as modifying self in-place."""
        self._modifies_self = True
        self._side_effects.add(SideEffect.MODIFIES_SELF)
        return self
    
    def returns_self(self) -> ContractBuilder:
        """Mark as returning self."""
        self._returns_self = True
        return self
    
    def preserves_device(self) -> ContractBuilder:
        """Output on same device as input."""
        self._preserves_device = True
        return self
    
    def device_from(self, arg: str) -> ContractBuilder:
        """Output device from specific argument."""
        self._device_from_arg = arg
        return self
    
    def preserves_shape(self) -> ContractBuilder:
        """Output has same shape as input."""
        self._preserves_shape = True
        return self
    
    def preserves_dtype(self) -> ContractBuilder:
        """Output has same dtype as input."""
        self._preserves_dtype = True
        return self
    
    def output_shape(self, fn: Callable[..., Shape]) -> ContractBuilder:
        """Set output shape function."""
        self._output_shape_fn = fn
        return self
    
    def parameters(self, *params: str) -> ContractBuilder:
        """Set parameter names."""
        self._parameters = list(params)
        return self
    
    def build(self) -> LibraryContract:
        """Build the contract."""
        if self._kind == ContractKind.METHOD:
            return MethodContract(
                name=self.name,
                module=self.module,
                kind=self._kind,
                description=self._description,
                return_interval=self._return_interval,
                return_interval_fn=self._return_interval_fn,
                guarantees_positive=self._guarantees_positive,
                guarantees_non_negative=self._guarantees_non_negative,
                guarantees_non_zero=self._guarantees_non_zero,
                guarantees_finite=self._guarantees_finite,
                preconditions=self._preconditions,
                postconditions=self._postconditions,
                invariants=self._invariants,
                side_effects=self._side_effects,
                preserves_device=self._preserves_device,
                device_from_arg=self._device_from_arg,
                preserves_shape=self._preserves_shape,
                output_shape_fn=self._output_shape_fn,
                preserves_dtype=self._preserves_dtype,
                output_dtype_fn=self._output_dtype_fn,
                class_name=self._class_name,
                modifies_self=self._modifies_self,
                returns_self=self._returns_self,
            )
        elif self._kind == ContractKind.PROPERTY:
            return PropertyContract(
                name=self.name,
                module=self.module,
                kind=self._kind,
                description=self._description,
                return_interval=self._return_interval,
                return_interval_fn=self._return_interval_fn,
                guarantees_positive=self._guarantees_positive,
                guarantees_non_negative=self._guarantees_non_negative,
                guarantees_non_zero=self._guarantees_non_zero,
                guarantees_finite=self._guarantees_finite,
                class_name=self._class_name,
            )
        elif self._kind == ContractKind.MODULE:
            return ModuleContract(
                name=self.name,
                module=self.module,
                kind=self._kind,
                description=self._description,
                return_interval=self._return_interval,
                return_interval_fn=self._return_interval_fn,
            )
        else:
            return FunctionContract(
                name=self.name,
                module=self.module,
                kind=self._kind,
                description=self._description,
                return_interval=self._return_interval,
                return_interval_fn=self._return_interval_fn,
                guarantees_positive=self._guarantees_positive,
                guarantees_non_negative=self._guarantees_non_negative,
                guarantees_non_zero=self._guarantees_non_zero,
                guarantees_finite=self._guarantees_finite,
                preconditions=self._preconditions,
                postconditions=self._postconditions,
                invariants=self._invariants,
                side_effects=self._side_effects,
                preserves_device=self._preserves_device,
                device_from_arg=self._device_from_arg,
                preserves_shape=self._preserves_shape,
                output_shape_fn=self._output_shape_fn,
                preserves_dtype=self._preserves_dtype,
                output_dtype_fn=self._output_dtype_fn,
                parameters=self._parameters,
            )


# =============================================================================
# Helper Functions
# =============================================================================

def contract(name: str, module: str) -> ContractBuilder:
    """Start building a contract."""
    return ContractBuilder(name, module)


def interval_contract(name: str, module: str, lo: float, hi: float,
                      description: str = "") -> FunctionContract:
    """Create a simple interval contract."""
    return FunctionContract(
        name=name,
        module=module,
        description=description,
        return_interval=Interval(lo, hi),
    )


def positive_contract(name: str, module: str,
                      description: str = "") -> FunctionContract:
    """Create a contract for positive return values."""
    return FunctionContract(
        name=name,
        module=module,
        description=description,
        guarantees_positive=True,
        guarantees_non_negative=True,
        guarantees_non_zero=True,
    )


def non_negative_contract(name: str, module: str,
                          description: str = "") -> FunctionContract:
    """Create a contract for non-negative return values."""
    return FunctionContract(
        name=name,
        module=module,
        description=description,
        return_interval=Interval.non_negative(),
        guarantees_non_negative=True,
    )
