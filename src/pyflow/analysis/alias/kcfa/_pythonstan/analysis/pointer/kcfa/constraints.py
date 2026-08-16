"""Pointer constraints and constraint management.

This module defines the constraint types used in the pointer analysis and
provides efficient storage and indexing for constraint-based solving.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Set, Dict, Type, Tuple, Optional, List, TYPE_CHECKING, Union
from collections import defaultdict

if TYPE_CHECKING:
    from pyflow.analysis.alias.kcfa._pythonstan.ir import IRCall
    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRStatement
    from .context import CallSite
    from .variable import Variable, FieldAccess
    from .heap_model import Field
    from .pointer_flow_graph import SelectorNode
    from .object import AbstractObject, AllocSite
    from .context import Ctx, Scope

__all__ = [
    "Constraint",
    "CopyConstraint",
    "InheritanceConstraint",
    "BaseResolutionConstraint",
    "MROEntriesResultConstraint",
    "MROEntriesElementConstraint",
    "LoadConstraint",
    "AttrReadConstraint",
    "AttrWriteConstraint",
    "StoreConstraint",
    "AllocConstraint",
    "LoadSubscrConstraint",
    "StoreSubscrConstraint",
    "CallConstraint",
    "MetaclassCallConstraint",
    "MetaclassBaseCallConstraint",
    "InheritedMetaclassCallConstraint",
    "ClassBaseCallConstraint",
    "argument_source_signature",
    "ReturnConstraint",
    "RaiseConstraint",
    "SuperResolveConstraint",
    "YieldConstraint",
    "AwaitConstraint",
    "ConstraintManager"
]


def argument_source_signature(
    args: Tuple[Tuple[Any, bool], ...],
    kwargs: Tuple[Tuple[Optional[str], Any], ...],
    receiver: Optional[Any] = None,
) -> Tuple[Tuple[Any, ...], ...]:
    """Return the canonical ordered source signature used by PARAM contexts."""
    signature = []
    if receiver is not None:
        signature.append(("recv", receiver))
    for index, (argument, is_starred) in enumerate(args):
        tag = "star" if is_starred else "pos"
        signature.append((tag, index, argument))
    for index, (name, argument) in enumerate(kwargs):
        if name is None:
            signature.append(("dstar", index, argument))
        else:
            signature.append(("kw", name, argument))
    return tuple(signature)


class Constraint(ABC):
    """Base class for all pointer constraints.
    
    Constraints represent facts about pointer flow in the program.
    """
    
    @abstractmethod
    def variables(self) -> Set['Variable']:
        """Get all variables involved in this constraint.
        
        Returns:
            Set of variables
        """
        pass
    
    @abstractmethod
    def __str__(self) -> str:
        """String representation for debugging."""
        pass


@dataclass(frozen=True)
class CopyConstraint(Constraint):
    """Copy constraint: target = source.
    
    Represents assignment from one variable to another.
    
    Attributes:
        source: Source variable
        target: Target variable
    """
    
    source: 'Variable'
    target: 'Variable'
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        return {self.source, self.target}
    
    def __str__(self) -> str:
        return f"CopyConstraint: {self.target} = {self.source}"


@dataclass(frozen=True)
class LoadConstraint(Constraint):
    """Load constraint: target = base.field or target = base[index].
    
    Represents loading a field from an object or subscript access.
    
    Attributes:
        base: Base variable pointing to objects
        field: Field being loaded (for attribute access, None for subscript)
        target: Target variable receiving field value
        index: Index variable for subscript access (None for attribute access)
    """
    
    base: 'Variable'
    field: Optional['Field']
    target: 'Variable'
    index: Optional['Variable'] = None
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.base}
        if self.index:
            vars.add(self.index)
        return vars
    
    def __str__(self) -> str:
        if self.index:
            return f"LoadConstraint: {self.target} = {self.base}[{self.index}]"
        return f"LoadConstraint: {self.target} = {self.base}{self.field}"


@dataclass(frozen=True)
class AttrReadConstraint(Constraint):
    """Attribute read constraint: target = base.attr.
    
    Represents attribute reads that require descriptor/interceptor semantics.
    
    Attributes:
        base: Base variable pointing to objects
        attr: Attribute name or field key
        target: Target variable receiving the attribute value
        call_site: Call site metadata for context-sensitive processing
    """
    
    base: 'Variable'
    attr: Union[str, 'Field']
    target: 'Variable'
    call_site: 'CallSite'
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        return {self.base, self.target}
    
    def __str__(self) -> str:
        if isinstance(self.attr, str):
            attr_str = f".{self.attr}"
        else:
            attr_str = str(self.attr)
        return f"AttrReadConstraint: {self.target} = {self.base}{attr_str}"


@dataclass(frozen=True)
class AttrWriteConstraint(Constraint):
    """Attribute write constraint: base.attr = source.
    
    Represents attribute writes that require descriptor/interceptor semantics.
    
    Attributes:
        base: Base variable pointing to objects
        attr: Attribute name or field key
        source: Source variable being stored
        call_site: Call site metadata for context-sensitive processing
    """
    
    base: 'Variable'
    attr: Union[str, 'Field']
    source: 'Variable'
    call_site: 'CallSite'
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        return {self.base, self.source}
    
    def __str__(self) -> str:
        if isinstance(self.attr, str):
            attr_str = f".{self.attr}"
        else:
            attr_str = str(self.attr)
        return f"AttrWriteConstraint: {self.base}{attr_str} = {self.source}"


@dataclass(frozen=True)
class InheritanceConstraint(Constraint):
    """Inheritance constraint: target.obj.class(.., base, ...) and base.field -> target
    
    Represents loading a field inherit from the index-th base class.
    
    Attributes:
        base: Base variable pointing to base class objects
        field: Field being loaded
        target: Target field access
        index: Index of the base class in the inheritance chain
    """
    
    base: 'Variable'
    field: Optional['Field']
    target: 'SelectorNode'
    index: int = 0
    owner: Optional['AbstractObject'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        return {self.base}
    
    def __str__(self) -> str:
        return f"InheritanceConstraint: {self.base}.{self.field} -[{self.index}]-> {self.target}"


@dataclass(frozen=True)
class BaseResolutionConstraint(Constraint):
    """Resolve one syntactic class base into an effective base sequence."""

    base: 'Variable'
    owner: 'AbstractObject'
    position: int
    original_bases: 'Variable'

    def variables(self) -> Set['Variable']:
        return {self.base, self.original_bases}

    def __str__(self) -> str:
        return f"BaseResolutionConstraint: {self.owner}[{self.position}] <- {self.base}"


@dataclass(frozen=True)
class MROEntriesResultConstraint(Constraint):
    """Validate and unpack a ``__mro_entries__`` return value."""

    result: 'Variable'
    owner: 'AbstractObject'
    position: int

    def variables(self) -> Set['Variable']:
        return {self.result}

    def __str__(self) -> str:
        return f"MROEntriesResultConstraint: {self.owner}[{self.position}] <- {self.result}"


@dataclass(frozen=True)
class MROEntriesElementConstraint(Constraint):
    """Refresh an effective base sequence when a tuple element grows."""

    element: 'Variable'
    elements: Tuple['Variable', ...]
    owner: 'AbstractObject'
    position: int

    def variables(self) -> Set['Variable']:
        return set(self.elements)

    def __str__(self) -> str:
        return f"MROEntriesElementConstraint: {self.owner}[{self.position}]"


@dataclass(frozen=True)
class SuperResolveConstraint(Constraint):
    """Constraint to resolve super() arguments and populate SuperObject.
    
    This constraint is triggered when super() result's points-to set contains
    a SuperObject allocation. It resolves the class and instance arguments:
    
    - Explicit: super(Class, obj) - resolve from provided variables
    - Implicit: super() - resolve from __class__ cell var and first parameter
    
    Once resolved, updates the SuperObject with current_class and instance_obj.
    
    Attributes:
        target: Variable pointing to SuperObject allocation
        class_var: Variable for class argument (None for implicit)
        instance_var: Variable for instance argument (None for implicit)
        implicit: True if super() called without arguments
    """
    
    target: 'Variable'
    class_var: Optional['Variable']
    instance_var: Optional['Variable']
    implicit: bool = False
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.target}
        if self.class_var:
            vars.add(self.class_var)
        if self.instance_var:
            vars.add(self.instance_var)
        return vars
    
    def __str__(self) -> str:
        if self.implicit:
            return f"SuperResolveConstraint: {self.target} = super() (implicit)"
        return f"SuperResolveConstraint: {self.target} = super({self.class_var}, {self.instance_var})"


@dataclass(frozen=True)
class LoadSubscrConstraint(Constraint):
    """Load constraint: target = base.field or target = base[index].
    
    Represents loading a field from an object or subscript access.
    
    Attributes:
        base: Base variable pointing to objects
        field: Field being loaded (for attribute access, None for subscript)
        target: Target variable receiving field value
        index: Index variable for subscript access (None for attribute access)
    """

    target: 'Variable'    
    base: 'Variable'
    index: 'Variable'
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.index}
        return vars
    
    def __str__(self) -> str:
        return f"LoadSubscrConstraint: {self.target} = {self.base}[{self.index}]"


@dataclass(frozen=True)
class StoreConstraint(Constraint):
    """Store constraint: base.field = source or base[index] = source.
    
    Represents storing to a field of an object or subscript access.
    
    Attributes:
        base: Base variable pointing to objects
        field: Field being stored to (for attribute access, None for subscript)
        source: Source variable being stored
        index: Index variable for subscript access (None for attribute access)
    """
    
    base: 'Variable'
    field: Optional['Field']
    source: 'Variable'
    index: Optional['Variable'] = None
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.base}
        return vars
    
    def __str__(self) -> str:
        if self.index:
            return f"StoreConstraint: {self.base}[{self.index}] = {self.source}"
        return f"StoreConstraint: {self.base}{self.field} = {self.source}"


@dataclass(frozen=True)
class StoreSubscrConstraint(Constraint):
    """Store constraint: base.field = source or base[index] = source.
    
    Represents storing to a field of an object or subscript access.
    
    Attributes:
        base: Base variable pointing to objects
        field: Field being stored to (for attribute access, None for subscript)
        source: Source variable being stored
        index: Index variable for subscript access (None for attribute access)
    """
    
    base: 'Variable'
    index: 'Variable'
    source: 'Variable'
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.index}
        if self.index:
            vars.add(self.index)
        return vars
    
    def __str__(self) -> str:
        return f"StoreSubscrConstraint: {self.base}[{self.index}] = {self.source}"


@dataclass(frozen=True)
class AllocConstraint(Constraint):
    """Allocation constraint: target = new Object.
    
    Represents object allocation.
    
    Attributes:
        target: Target variable receiving new object
        alloc_site: Allocation site of new object
    """
    
    target: 'Variable'
    alloc_site: 'AllocSite'
    
    def __post_init__(self):
        from .object import AllocSite
        from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRStatement
        
        assert isinstance(self.alloc_site, AllocSite), f"alloc_site must be an AllocSite, but got {type(self.alloc_site)}"
        assert isinstance(self.alloc_site.stmt, IRStatement), f"alloc_site.stmt must be an IRStatement, but got {type(self.alloc_site.stmt)}"
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        return {self.target}
    
    def __str__(self) -> str:
        return f"AllocConstraint: {self.target} = new {self.alloc_site}"


@dataclass(frozen=True)
class CallConstraint(Constraint):
    """Call constraint: target = callee(args...).
    
    Represents function call. Actual call edges are resolved dynamically
    based on what callee points to.
    
    Attributes:
        callee: Variable holding callable object
        args: Tuple of argument variables
        target: Optional target variable for return value
        call_site: Call site metadata bound to an IR statement
    """
    
    callee: 'Variable'
    args: Tuple['Variable', ...]
    kwargs: Tuple[Tuple[Optional[str], 'Variable'], ...]
    target: Optional['Variable']
    call_site: 'CallSite'
    starred: Tuple[bool, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kwargs, tuple):
            object.__setattr__(self, "kwargs", tuple(self.kwargs))
        if not self.starred:
            object.__setattr__(self, "starred", (False,) * len(self.args))
        elif len(self.starred) != len(self.args):
            raise ValueError("starred flags must match positional arguments")

    def iter_args(self):
        return zip(self.args, self.starred)
    
    @property
    def stmt(self) -> 'IRStatement':
        return self.call_site.statement
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.callee, *self.args}
        vars.update(var for _, var in self.kwargs)
        if self.target:
            vars.add(self.target)
        return vars
    
    def __str__(self) -> str:
        args_str = ", ".join(str(a) for a in self.args)
        if self.target:
            return f"{self.target} = {self.callee}({args_str})"
        return f"CallConstraint: {self.callee}({args_str})"


@dataclass(frozen=True)
class MetaclassCallConstraint(Constraint):
    """Deferred dispatch of a class call through an explicit metaclass."""

    metaclass: 'Variable'
    metaclass_scope: 'Scope'
    class_object: 'AbstractObject'
    call: CallConstraint

    def variables(self) -> Set['Variable']:
        return {self.metaclass}

    def __str__(self) -> str:
        return f"MetaclassCallConstraint: type({self.class_object})({self.call})"


@dataclass(frozen=True)
class MetaclassBaseCallConstraint(Constraint):
    """Reconsider metaclass ``__call__`` lookup when a base grows."""

    base: 'Variable'
    base_scope: 'Scope'
    metaclass_object: 'AbstractObject'
    class_object: 'AbstractObject'
    call: CallConstraint

    def variables(self) -> Set['Variable']:
        return {self.base}

    def __str__(self) -> str:
        return f"MetaclassBaseCallConstraint: {self.metaclass_object}.{self.base}"


@dataclass(frozen=True)
class InheritedMetaclassCallConstraint(Constraint):
    """Deferred lookup of a class call's metaclass through a base binding."""

    base: 'Variable'
    base_scope: 'Scope'
    class_object: 'AbstractObject'
    call: CallConstraint

    def variables(self) -> Set['Variable']:
        return {self.base}

    def __str__(self) -> str:
        return f"InheritedMetaclassCallConstraint: type({self.base})({self.call})"


@dataclass(frozen=True)
class ClassBaseCallConstraint(Constraint):
    """Retry a class call when an effective base position changes."""

    base: 'Variable'
    base_scope: 'Scope'
    class_object: 'AbstractObject'
    call: CallConstraint

    def variables(self) -> Set['Variable']:
        return {self.base}

    def __str__(self) -> str:
        return f"ClassBaseCallConstraint: {self.class_object}({self.call})"


@dataclass(frozen=True)
class ReturnConstraint(Constraint):
    """Return constraint: connect callee return to caller target.
    
    Represents flow of return value from callee to caller.
    
    Attributes:
        callee_return: Special $return variable in callee
        caller_target: Target variable in caller
    """
    
    callee_return: 'Variable'
    caller_target: 'Variable'
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        return {self.callee_return, self.caller_target}
    
    def __str__(self) -> str:
        return f"ReturnConstraint: {self.caller_target} = return({self.callee_return})"


@dataclass(frozen=True)
class RaiseConstraint(Constraint):
    """A value and optional cause escaping through exception propagation."""

    exception: Optional['Variable']
    cause: Optional['Variable'] = None
    site: Optional['IRStatement'] = None

    def variables(self) -> Set['Variable']:
        return {var for var in (self.exception, self.cause) if var is not None}

    def __str__(self) -> str:
        if self.cause is not None:
            return f"RaiseConstraint: raise {self.exception} from {self.cause}"
        return f"RaiseConstraint: raise {self.exception}"


@dataclass(frozen=True)
class YieldConstraint(Constraint):
    """Yield constraint: [target =] yield value.
    
    Represents yielding a value from a generator function. The yielded value
    flows to the generator object's elem() field. If a target is present,
    the value sent to the generator flows into the target.
    
    Attributes:
        value: Variable holding the yielded value (or None for bare yield)
        target: Variable to receive sent value (for target = yield value)
        generator_var: Variable holding the current generator object ($generator)
    """
    
    value: Optional['Variable']
    target: Optional['Variable']
    generator_var: 'Variable'
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.generator_var}
        if self.value:
            vars.add(self.value)
        if self.target:
            vars.add(self.target)
        return vars
    
    def __str__(self) -> str:
        if self.target and self.value:
            return f"YieldConstraint: {self.target} = yield {self.value}"
        elif self.value:
            return f"YieldConstraint: yield {self.value}"
        else:
            return f"YieldConstraint: yield"


@dataclass(frozen=True)
class AwaitConstraint(Constraint):
    """Await constraint: target = await value.
    
    Represents awaiting a coroutine/awaitable. The awaited value's result
    (from its $await_result field) flows into the target variable.
    
    Attributes:
        awaitable: Variable holding the awaitable/coroutine object
        target: Variable to receive the await result (or None)
    """
    
    awaitable: 'Variable'
    target: Optional['Variable']
    site: Optional['IRStatement'] = None
    
    def variables(self) -> Set['Variable']:
        """Get variables involved."""
        vars = {self.awaitable}
        if self.target:
            vars.add(self.target)
        return vars
    
    def __str__(self) -> str:
        if self.target:
            return f"AwaitConstraint: {self.target} = await {self.awaitable}"
        return f"AwaitConstraint: await {self.awaitable}"


class ConstraintManager:
    """Efficient constraint storage and indexing.
    
    Provides fast lookup of constraints by variable and by type.
    """
    
    def __init__(self):
        """Initialize empty constraint manager."""
        self._constraints: Set[Tuple['Scope', Constraint]] = set()
        self._by_variable: Dict['Variable', List[Tuple['Scope', Constraint]]] = defaultdict(list)
        self._by_type: Dict[Type[Constraint], List[Tuple['Scope', Constraint]]] = defaultdict(list)
    
    def add(self, scope, var, constraint: Constraint) -> bool:
        """Add constraint to manager.
        
        Args:
            constraint: Constraint to add
        
        Returns:
            True if constraint was new (not duplicate)
        """
        if (scope, constraint) in self._constraints:
            return False
   
        self._constraints.add((scope, constraint))
        self._by_variable[var].append((scope, constraint))
        self._by_type[type(constraint)].append((scope, constraint))

        return True
    
    def remove(self, scope, var, constraint: Constraint) -> bool:
        """Remove constraint from manager.
        
        Args:
            constraint: Constraint to remove
        
        Returns:
            True if constraint existed
        """
        if (scope, constraint) not in self._constraints:
            return False
        
        self._constraints.remove((scope, constraint))
        
        # Remove from variable index
        for involved_var in constraint.variables():
            scoped_list = self._by_variable.get(involved_var)
            if not scoped_list:
                continue
            self._by_variable[involved_var] = [
                (s, c) for (s, c) in scoped_list if not (s == scope and c == constraint)
            ]
        
        # Remove from type index
        scoped_list = self._by_type.get(type(constraint))
        if scoped_list:
            self._by_type[type(constraint)] = [
                (s, c) for (s, c) in scoped_list if not (s == scope and c == constraint)
            ]
        
        return True
    
    def get_by_variable(self, var: 'Variable') -> List[Constraint]:
        """Get all constraints involving variable.
        
        Args:
            var: Variable to query
        
        Returns:
            Set of constraints (empty if none)
        """
        return [constraint for _, constraint in self._by_variable.get(var, list())]
    
    def iter_scoped_by_variable(self, var: 'Variable') -> List[Tuple['Scope', Constraint]]:
        """Iterate constraints with their defining scope for a variable."""
        return list(self._by_variable.get(var, list()))
    
    def get_by_type(self, constraint_type: Type[Constraint]) -> List[Constraint]:
        """Get all constraints of given type.
        
        Args:
            constraint_type: Type to query
        
        Returns:
            Set of constraints of that type
        """
        return [constraint for _, constraint in self._by_type.get(constraint_type, list())]
    
    def all(self) -> Set[Constraint]:
        """Get all constraints.
        
        Returns:
            Copy of all constraints
        """
        return self._constraints.copy()
    
    def __len__(self) -> int:
        """Get number of constraints."""
        return len(self._constraints)
