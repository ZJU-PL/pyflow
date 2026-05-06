"""
Context-sensitive type tracking for improved taint analysis precision.

This module tracks the concrete Python type of values after conversions,
allowing us to:
1. Determine if a value is safe for type-specific sinks (e.g., int for SQL)
2. Improve precision by knowing when values cannot contain injection payloads
3. Support type-narrowing sanitizers (int() removes string injection risk)

The type tracker integrates with the taint lattice to provide both
taint information and type information for each value.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, FrozenSet
import z3


class ConcreteType(IntEnum):
    """Python concrete types that can be tracked."""
    UNKNOWN = 0      # Type not known/tracked
    NONE = 1         # None
    BOOL = 2         # bool
    INT = 3          # int (unbounded)
    FLOAT = 4        # float
    STR = 5          # str
    BYTES = 6        # bytes
    LIST = 7         # list
    TUPLE = 8        # tuple
    DICT = 9         # dict
    SET = 10         # set
    DATETIME = 11    # datetime.datetime
    DATE = 12        # datetime.date
    UUID = 13        # uuid.UUID
    IPADDRESS = 14   # ipaddress.IPAddress
    PATH = 15        # pathlib.Path
    ENUM = 16        # enum.Enum subclass


# ============================================================================
# TYPE LABEL (CONCRETE)
# ============================================================================

@dataclass(frozen=True)
class TypeLabel:
    """
    Concrete type label tracking the Python type of a value.
    
    This is tracked alongside the taint label to provide additional
    precision for security analysis.
    
    Attributes:
        concrete_type: The concrete Python type (if known)
        conversion_history: Sequence of conversions applied (for debugging)
    """
    concrete_type: ConcreteType = ConcreteType.UNKNOWN
    conversion_history: FrozenSet[str] = field(default_factory=frozenset)
    
    @staticmethod
    def unknown() -> 'TypeLabel':
        """Unknown type (default)."""
        return TypeLabel()
    
    @staticmethod
    def from_type(typ: ConcreteType, conversion: str = "") -> 'TypeLabel':
        """Create label for a specific type."""
        history = frozenset({conversion}) if conversion else frozenset()
        return TypeLabel(concrete_type=typ, conversion_history=history)
    
    def convert_to(self, new_type: ConcreteType, conversion: str) -> 'TypeLabel':
        """Apply type conversion."""
        return TypeLabel(
            concrete_type=new_type,
            conversion_history=self.conversion_history | {conversion}
        )
    
    def is_numeric(self) -> bool:
        """Check if this is a numeric type (int/float)."""
        return self.concrete_type in (ConcreteType.INT, ConcreteType.FLOAT, ConcreteType.BOOL)
    
    def is_string_like(self) -> bool:
        """Check if this is a string-like type."""
        return self.concrete_type in (ConcreteType.STR, ConcreteType.BYTES)
    
    def is_safe_for_sql(self) -> bool:
        """
        Check if this type is inherently safe for SQL (cannot contain injection).
        
        Numeric types (int, float, bool) and structured types (datetime, UUID)
        cannot contain SQL injection payloads.
        """
        return self.concrete_type in (
            ConcreteType.INT, ConcreteType.FLOAT, ConcreteType.BOOL,
            ConcreteType.DATETIME, ConcreteType.DATE, ConcreteType.UUID
        )
    
    def is_safe_for_path(self) -> bool:
        """
        Check if this type is safe for file paths.
        
        Path objects are canonicalized. UUIDs are safe as path components.
        """
        return self.concrete_type in (ConcreteType.PATH, ConcreteType.UUID, ConcreteType.INT)
    
    def is_safe_for_command(self) -> bool:
        """
        Check if this type is safe for command injection.
        
        Numeric types cannot contain shell metacharacters.
        """
        return self.concrete_type in (
            ConcreteType.INT, ConcreteType.FLOAT, ConcreteType.BOOL,
            ConcreteType.UUID
        )


# ============================================================================
# TYPE-AWARE TAINT LABEL
# ============================================================================

@dataclass(frozen=True)
class TypeAwareTaintLabel:
    """
    Combined taint and type label for context-sensitive analysis.
    
    This allows us to answer questions like:
    - "Is this value tainted?" (from taint_label)
    - "What type is this value?" (from type_label)
    - "Is this tainted value safe despite taint?" (type + taint together)
    """
    taint_label: 'TaintLabel'  # Will be imported from taint_lattice
    type_label: TypeLabel
    
    def is_safe_for_sink_considering_type(self, sink_type: 'SinkType') -> bool:
        """
        Check if value is safe for sink, considering both taint and type.
        
        A value may be tainted but still safe if its type prevents exploitation:
        - int(user_input) → tainted but safe for SQL (no injection possible)
        - uuid.UUID(user_input) → tainted but safe for paths
        - float(user_input) → tainted but safe for commands
        
        This is MORE PRECISE than pure taint tracking.
        """
        # Import here to avoid circular dependency
        from .taint_lattice import SinkType
        
        # First check taint-based safety
        if self.taint_label.is_safe_for_sink(sink_type):
            return True
        
        # If tainted but type-safe, still safe
        if sink_type == SinkType.SQL_EXECUTE and self.type_label.is_safe_for_sql():
            return True
        if sink_type == SinkType.FILE_PATH and self.type_label.is_safe_for_path():
            return True
        if sink_type == SinkType.COMMAND_SHELL and self.type_label.is_safe_for_command():
            return True
        
        return False
    
    def join(self, other: 'TypeAwareTaintLabel') -> 'TypeAwareTaintLabel':
        """
        Join two type-aware labels.
        
        - Taint labels join normally (⊔)
        - Types become UNKNOWN if they differ (loss of precision)
        """
        merged_taint = self.taint_label.join(other.taint_label)
        
        # Type tracking: if types match, keep it; otherwise UNKNOWN
        if self.type_label.concrete_type == other.type_label.concrete_type:
            merged_type = TypeLabel(
                concrete_type=self.type_label.concrete_type,
                conversion_history=self.type_label.conversion_history | other.type_label.conversion_history
            )
        else:
            merged_type = TypeLabel.unknown()
        
        return TypeAwareTaintLabel(
            taint_label=merged_taint,
            type_label=merged_type
        )


# ============================================================================
# TYPE CONVERSION MAPPINGS
# ============================================================================

# Map function names to resulting types
TYPE_CONVERSION_FUNCTIONS = {
    # Builtin conversions
    'int': ConcreteType.INT,
    'builtins.int': ConcreteType.INT,
    'float': ConcreteType.FLOAT,
    'builtins.float': ConcreteType.FLOAT,
    'bool': ConcreteType.BOOL,
    'builtins.bool': ConcreteType.BOOL,
    'str': ConcreteType.STR,
    'builtins.str': ConcreteType.STR,
    'bytes': ConcreteType.BYTES,
    'builtins.bytes': ConcreteType.BYTES,
    
    # String methods (return bool - used for validation)
    'str.isdigit': ConcreteType.BOOL,
    'str.isalpha': ConcreteType.BOOL,
    'str.isalnum': ConcreteType.BOOL,
    'str.isnumeric': ConcreteType.BOOL,
    'str.isdecimal': ConcreteType.BOOL,
    
    # Datetime conversions
    'datetime.datetime.fromisoformat': ConcreteType.DATETIME,
    'datetime.datetime.strptime': ConcreteType.DATETIME,
    'datetime.date.fromisoformat': ConcreteType.DATE,
    
    # UUID
    'uuid.UUID': ConcreteType.UUID,
    
    # IP addresses
    'ipaddress.ip_address': ConcreteType.IPADDRESS,
    'ipaddress.IPv4Address': ConcreteType.IPADDRESS,
    'ipaddress.IPv6Address': ConcreteType.IPADDRESS,
    
    # Pathlib
    'pathlib.Path': ConcreteType.PATH,
    'pathlib.PosixPath': ConcreteType.PATH,
    'pathlib.WindowsPath': ConcreteType.PATH,
}


def get_conversion_result_type(func_name: str) -> Optional[ConcreteType]:
    """Get the resulting type after a type conversion function call."""
    return TYPE_CONVERSION_FUNCTIONS.get(func_name)


def is_type_conversion(func_name: str) -> bool:
    """Check if a function is a known type conversion."""
    return func_name in TYPE_CONVERSION_FUNCTIONS


# ============================================================================
# SYMBOLIC TYPE TRACKING (for Z3)
# ============================================================================

@dataclass
class SymbolicTypeLabel:
    """
    Symbolic type label for Z3-based reasoning.
    
    This uses Z3 bitvectors to represent type information symbolically,
    enabling barrier certificate synthesis over types.
    """
    # Type as Z3 bitvector (17 possible types → 5 bits needed)
    type_bv: z3.BitVecRef
    
    @staticmethod
    def fresh(name: str) -> 'SymbolicTypeLabel':
        """Create fresh symbolic type variable."""
        return SymbolicTypeLabel(
            type_bv=z3.BitVec(f"{name}_type", 5)
        )
    
    @staticmethod
    def from_concrete(concrete: ConcreteType, name: str = "type") -> 'SymbolicTypeLabel':
        """Create symbolic type from concrete type."""
        return SymbolicTypeLabel(
            type_bv=z3.BitVecVal(concrete.value, 5)
        )
    
    def is_numeric_constraint(self) -> z3.BoolRef:
        """Z3 constraint: type is numeric (INT, FLOAT, or BOOL)."""
        return z3.Or(
            self.type_bv == ConcreteType.INT.value,
            self.type_bv == ConcreteType.FLOAT.value,
            self.type_bv == ConcreteType.BOOL.value
        )
    
    def is_safe_for_sql_constraint(self) -> z3.BoolRef:
        """Z3 constraint: type is inherently SQL-safe."""
        return z3.Or(
            self.type_bv == ConcreteType.INT.value,
            self.type_bv == ConcreteType.FLOAT.value,
            self.type_bv == ConcreteType.BOOL.value,
            self.type_bv == ConcreteType.DATETIME.value,
            self.type_bv == ConcreteType.DATE.value,
            self.type_bv == ConcreteType.UUID.value
        )
    
    def is_safe_for_command_constraint(self) -> z3.BoolRef:
        """Z3 constraint: type is command-safe."""
        return z3.Or(
            self.type_bv == ConcreteType.INT.value,
            self.type_bv == ConcreteType.FLOAT.value,
            self.type_bv == ConcreteType.BOOL.value,
            self.type_bv == ConcreteType.UUID.value
        )


__all__ = [
    'ConcreteType', 'TypeLabel', 'TypeAwareTaintLabel',
    'SymbolicTypeLabel', 'get_conversion_result_type', 'is_type_conversion'
]
