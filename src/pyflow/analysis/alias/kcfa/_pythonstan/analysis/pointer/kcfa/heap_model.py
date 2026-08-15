"""Heap model and field abstraction for pointer analysis.

This module defines the abstraction of heap storage including field keys
for attribute access, container elements, and dictionary values.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Tuple, Set, TYPE_CHECKING

from .variable import VariableKind

if TYPE_CHECKING:
    from .object import AbstractObject, FunctionObject
    from .variable import Variable, FieldAccess
    from .context import AbstractContext, Ctx, Scope, AllocSite

__all__ = ["FieldKind", "Field", "attr", "elem", "key", "value", "unknown", "HeapModel"]

class FieldKind(Enum):
    """Kinds of heap fields."""
    
    ATTRIBUTE = "attr"
    ELEMENT = "elem"
    VALUE = "value"
    UNKNOWN = "unknown"
    POSITION = "position"
    KEY = "key"


@dataclass(frozen=True)
class Field:
    """Heap field key for object field access.
    
    Fields abstract over different kinds of object field access:
    - ATTRIBUTE: Named attribute access (obj.name)
    - ELEMENT: Container element access (list/set/tuple elements)
    - VALUE: Dictionary value access (dict values, key-insensitive)
    - UNKNOWN: Dynamic/unknown attribute access
    
    Attributes:
        kind: Type of field access
        name: Field name for ATTRIBUTE kind, None otherwise
    """
    
    kind: FieldKind
    name: Optional[str] = None
    index: Optional[int] = None
    
    def __post_init__(self):
        """Validate field constraints."""
        if self.kind == FieldKind.ATTRIBUTE and self.name is None:
            raise ValueError("ATTRIBUTE field must have name")
        if self.kind == FieldKind.KEY and self.name is None:
            raise ValueError("KEY field must have name")
        if self.kind == FieldKind.POSITION and self.index is None:
            raise ValueError("POSITION field must have index")
        if self.kind in [FieldKind.ELEMENT, FieldKind.VALUE, FieldKind.UNKNOWN]:
            if self.name is not None or self.index is not None:
                raise ValueError(f"{self.kind.value} field should not have name or index")
    
    def __str__(self) -> str:
        """String representation for debugging."""
        if self.kind == FieldKind.ATTRIBUTE:
            return f".{self.name}"
        if self.kind == FieldKind.POSITION:
            return f"[{self.index}]"
        if self.kind == FieldKind.KEY:
            return f"['{self.name}']"
        return f".{self.kind.value}"

def key(key_name: str) -> Field:
    """Create key field for specific key/index access. Used for dictionary and list/tuple elements.
    
    Used for dict["key"] where key is statically known constant.
    
    Args:
        key_name: Dictionary key as string
    
    Returns:
        Field for specific key access
    """
    if not isinstance(key_name, str):
        key_name = str(key_name)
    return Field(FieldKind.KEY, key_name, None)


def attr(name: str) -> Field:
    """Create attribute field key.
    
    Args:
        name: Attribute name
    
    Returns:
        Field for obj.name access
    
    Example:
        >>> attr("foo")
        Field(kind=FieldKind.ATTRIBUTE, name="foo")
    """
    return Field(FieldKind.ATTRIBUTE, name, None)


def elem() -> Field:
    """Create element field key for containers.
    
    Used for dict/list/tuple/set elements where we abstract over all indices.
    
    Returns:
        Field for generic container element access
    
    Example:
        >>> elem()
        Field(kind=FieldKind.ELEMENT, name=None, index=None)
    """
    return Field(FieldKind.ELEMENT, None, None)


def value() -> Field:
    """Create value field key for dictionaries.
    
    Used for dict values where we abstract over all keys.
    
    Returns:
        Field for generic dictionary value access
    
    Example:
        >>> value()
        Field(kind=FieldKind.VALUE, name=None, index=None)
    """
    return Field(FieldKind.VALUE, None, None)


def unknown() -> Field:
    """Create unknown field key for dynamic access.
    
    Used when attribute name cannot be determined statically.
    
    Returns:
        Field for unknown attribute access
    
    Example:
        >>> unknown()
        Field(kind=FieldKind.UNKNOWN, name=None)
    """
    return Field(FieldKind.UNKNOWN, None, None)


class HeapModel:
    """Heap model for pointer analysis.
    
    Maintains the heap and field accesses.
    """
    
    heap: 'Dict[Tuple[Scope, AbstractContext], Dict[Tuple[str, VariableKind], Ctx[Variable]]]'
    prev_scope: 'Dict[Scope, Scope]'
    objects: 'Dict[Tuple[Scope, AbstractContext, AllocSite], AbstractObject]'
    cell_vars: 'Dict[FunctionObject, Dict[str, Set[Ctx[Variable]]]]'
    global_vars: 'Dict[FunctionObject, Dict[str, Set[Ctx[Variable]]]]'
    nonlocal_vars: 'Dict[FunctionObject, Dict[str, Set[Ctx[Variable]]]]'
    
    def __init__(self):
        self.heap = {}
        self.field_accesses = {}
        self.objects = {}
        self.cell_vars = {}
        self.global_vars = {}
        self.nonlocal_vars = {}

    def get_variable(self, scope: 'Scope', context: 'AbstractContext', var: 'Variable') -> Optional['Ctx[Variable]']:
        ctx_key = self._get_var_key(scope, context, var)
        
        registers = self.heap.get(ctx_key, {})
        return registers.get(var.name, None)

    def set_variable(self, scope: 'Scope', context: 'AbstractContext', var: 'Variable', ctx_var: 'Ctx[Variable]'):
        ctx_key = self._get_var_key(scope, context, var)
        
        registers = self.heap.get(ctx_key, None)
        if registers is None:
            registers = {}
            self.heap[ctx_key] = registers
        registers[var.name] = ctx_var  # TODO whether use context or scope.context?
    
    def _get_var_key(self, scope: 'Scope', context: 'AbstractContext', var: 'Variable'):
        if var.kind == VariableKind.TEMPORARY:
            return (context, scope)
        
        if var.kind == VariableKind.GLOBAL:
            return (scope.module,)
        return (context, scope)

    def get_all_variables(self, scope: 'Scope', context: 'AbstractContext') -> Set['Ctx[Variable]']:
        ctx_key = (scope, )
        return self.heap.get(ctx_key, {}).values()
    
    def set_obj(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocSite', o: "AbstractObject"):
        # print(f"New object: {o}")
        self.objects[(context, c.stmt, c.kind)] = o
    
    def get_obj(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocSite') -> Optional['AbstractObject']:
        return self.objects.get((context, c.stmt, c.kind), None)
    
    def get_cell_vars(self, obj: 'FunctionObject') -> 'Dict[str, Ctx[Variable]]':
        return self.cell_vars.get(obj, {})
    
    def get_global_vars(self, obj: 'FunctionObject') -> 'Dict[str, Ctx[Variable]]':
        return self.global_vars.get(obj, {})
    
    def get_nonlocal_vars(self, obj: 'FunctionObject') -> 'Dict[str, Ctx[Variable]]':
        return self.nonlocal_vars.get(obj, {})
