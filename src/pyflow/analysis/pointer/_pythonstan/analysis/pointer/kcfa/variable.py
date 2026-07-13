"""Program variables for pointer analysis.

This module defines the representation of program variables in the k-CFA pointer analysis.
Variables are context-sensitive and scoped.
"""

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Literal, Optional

from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRScope

if TYPE_CHECKING:
    from .context import AbstractContext
    from .object import AbstractObject
    from .heap_model import Field

__all__ = ["VariableKind", "Variable", "FieldAccess"]


class VariableKind(Enum):
    """Kinds of variables in Python programs."""
    
    LOCAL = "local"
    PARAMETER = "parameter"
    GLOBAL = "global"
    NONLOCAL = "nonlocal"
    CELL = "cell"
    TEMPORARY = "temporary"


@dataclass(frozen=True)
class Variable:
    """Program variable with scope and context.
    
    A variable represents a program location that holds references to objects.
    Variables are context-qualified to enable context-sensitive analysis.
    
    Attributes:
        name: Variable name (unqualified)
        scope: Enclosing scope
        context: Analysis context
        kind: Variable kind (local, parameter, etc.)
    """
    
    name: str
    kind: VariableKind = VariableKind.LOCAL
    
    def __post_init__(self):
        assert isinstance(self.name, str), f"Variable name must be a string, but got {type(self.name)}"
        assert isinstance(self.kind, VariableKind), f"Variable kind must be a VariableKind, but got {type(self.kind)}"
    
    def __str__(self) -> str:
        """String representation: name@kind"""
        assert self.name is not None, "Variable name is required"
        return f"[{self.kind.value}]{self.name}"
    
    @property
    def is_temporary(self) -> bool:
        """Check if this is a temporary variable."""
        return self.kind == VariableKind.TEMPORARY
    
    @property
    def is_global(self) -> bool:
        """Check if this is a global variable."""
        return self.kind == VariableKind.GLOBAL
    
    @property
    def is_local(self) -> bool:
        """Check if this is a local variable."""
        return self.kind == VariableKind.LOCAL
    
    @property
    def is_cell(self) -> bool:
        return self.kind == VariableKind.CELL
    
    @property
    def is_nonlocal(self) -> bool:
        return self.kind == VariableKind.NONLOCAL


@dataclass(frozen=True)
class FieldAccess:
    """Field access for variables.
    
    Attributes:
        variable: Variable fbeing accessed
        field: Field being accessed
    """

    obj: 'AbstractObject'
    field: 'Field'
    
    def __str__(self) -> str:
        return f"{self.obj}{self.field}"


class VariableFactory:
    """Helper for creating variables from IR information.
    
    This factory maintains consistent variable creation across the analysis.
    It is stateless and simply provides a convenient interface for Variable creation.
    """
    
    def __init__(self):
        """Initialize variable factory.
        
        The factory is stateless - no initialization needed.
        """
        pass
    
    def make_variable(
        self,
        name: str,
        kind: VariableKind = VariableKind.LOCAL
    ) -> Variable:
        """Create variable with given attributes.
        
        Args:
            name: Variable name
            scope: Enclosing scope
            context: Analysis context
            kind: Variable kind
        
        Returns:
            Created variable
        """
        return Variable(name=name, kind=kind)
    
    def make_field_access(
        self,
        obj: 'AbstractObject',
        field: 'Field'
    ) -> FieldAccess:
        """Create field access for variable.
        
        Args:
            obj: Object being accessed
            field: Field being accessed
        
        Returns:
            Created field access
        """
        return FieldAccess(obj=obj, field=field)
