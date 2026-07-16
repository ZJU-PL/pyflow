"""
PointerResults Protocol for AI consumption.

This module defines the interface that AI analysis uses to consume pointer analysis results.
The protocol is designed to provide sound abstractions and fallbacks for imprecise results.
"""

from typing import Protocol, Optional, Iterable, Set, Dict, Tuple, Any
from abc import ABC, abstractmethod


class FunctionSymbol(Protocol):
    """Represents a function in the program."""
    name: str


class CallSite(Protocol):
    """Represents a call site location."""
    site_id: str
    filename: str
    line: int
    col: int


class AbstractObject(Protocol):
    """Represents an abstract object in the heap."""
    alloc_id: str


class FieldKey(Protocol):
    """Represents a field access key (attribute, element, etc.)."""
    kind: str   # "attr" | "elem" | "value" | "unknown"
    name: Optional[str]


class Context(Protocol):
    """Represents analysis context for context-sensitive analysis."""
    call_string: Tuple[CallSite, ...]


class PointsToSet(Protocol):
    """Represents a points-to set of abstract objects."""
    
    def __iter__(self) -> Iterable[AbstractObject]:
        """Iterate over abstract objects in the points-to set."""
        ...
    
    def __len__(self) -> int:
        """Get the size of the points-to set."""
        ...


class PointerResults(Protocol):
    """
    Protocol for pointer analysis results consumed by AI analysis.
    
    All methods must provide sound over-approximations when precise results
    are unavailable. Unsafe pruning should be avoided.
    """
    
    def possible_callees(self, call_site: CallSite, ctx: Optional[Context] = None) -> Set[FunctionSymbol]:
        """
        Get possible callees for an indirect call site.
        
        Args:
            call_site: The call site to analyze
            ctx: Optional context for context-sensitive analysis
            
        Returns:
            Set of possible function targets. Returns over-approximation if unsure.
        """
        ...
    
    def points_to(self, var: str, ctx: Optional[Context] = None) -> PointsToSet:
        """
        Get the points-to set for a variable.
        
        Args:
            var: Variable name
            ctx: Optional context for context-sensitive analysis
            
        Returns:
            Points-to set. Returns over-approximation if unsure.
        """
        ...
    
    def field_points_to(self, obj: AbstractObject, field: FieldKey) -> PointsToSet:
        """
        Get the points-to set for a field of an object.
        
        Args:
            obj: The object containing the field
            field: The field key (attribute, element, etc.)
            
        Returns:
            Points-to set for the field. Returns over-approximation if unsure.
        """
        ...
    
    def may_alias(self, a_var: str, b_var: str, ctx: Optional[Context] = None) -> bool:
        """
        Check if two variables may alias.
        
        Args:
            a_var: First variable
            b_var: Second variable
            ctx: Optional context for context-sensitive analysis
            
        Returns:
            True if variables may alias, False if definitely not.
            Returns True (over-approximation) if unsure.
        """
        ...
    
    def is_singleton(self, target: Any, ctx: Optional[Context] = None) -> bool:
        """
        Check if a target (variable/object) points to exactly one abstract object.
        
        Args:
            target: The target to check (variable name or abstract object)
            ctx: Optional context for context-sensitive analysis
            
        Returns:
            True if target is a singleton, False otherwise.
            Returns False (under-approximation) if unsure.
        """
        ...
    
    def call_graph_successors(self, fn: FunctionSymbol) -> Set[FunctionSymbol]:
        """
        Get the call graph successors of a function.
        
        Args:
            fn: The function to get successors for
            
        Returns:
            Set of functions that may be called by fn.
            Returns over-approximation if unsure.
        """
        ...
    
    def pointer_digest_version(self) -> str:
        """
        Get a version string for the pointer analysis digest.
        
        Returns:
            Version string identifying the pointer analysis configuration.
        """
        ...


# Concrete implementations for field keys
class AttrFieldKey:
    """Field key for attribute access."""
    
    def __init__(self, name: str):
        self.kind = "attr"
        self.name = name
    
    def __str__(self) -> str:
        return f"attr:{self.name}"
    
    def __eq__(self, other) -> bool:
        return isinstance(other, AttrFieldKey) and self.name == other.name
    
    def __hash__(self) -> int:
        return hash(("attr", self.name))


class ElemFieldKey:
    """Field key for element access (lists, tuples)."""
    
    def __init__(self, index: Optional[int] = None):
        self.kind = "elem"
        self.name = str(index) if index is not None else None
    
    def __str__(self) -> str:
        return f"elem:{self.name}" if self.name else "elem:*"
    
    def __eq__(self, other) -> bool:
        return isinstance(other, ElemFieldKey) and self.name == other.name
    
    def __hash__(self) -> int:
        return hash(("elem", self.name))


class ValueFieldKey:
    """Field key for value access (dict values)."""
    
    def __init__(self, key: Optional[str] = None):
        self.kind = "value"
        self.name = key
    
    def __str__(self) -> str:
        return f"value:{self.name}" if self.name else "value:*"
    
    def __eq__(self, other) -> bool:
        return isinstance(other, ValueFieldKey) and self.name == other.name
    
    def __hash__(self) -> int:
        return hash(("value", self.name))


class UnknownFieldKey:
    """Field key for unknown/dynamic field access."""
    
    def __init__(self):
        self.kind = "unknown"
        self.name = None
    
    def __str__(self) -> str:
        return "unknown"
    
    def __eq__(self, other) -> bool:
        return isinstance(other, UnknownFieldKey)
    
    def __hash__(self) -> int:
        return hash(("unknown", None))


# Mock implementation for testing
class MockPointerResults:
    """
    Mock implementation of PointerResults for testing.
    
    Provides configurable behaviors for testing different pointer analysis scenarios.
    """
    
    def __init__(self, 
                 precise: bool = True,
                 singleton_vars: Set[str] = None,
                 alias_pairs: Set[Tuple[str, str]] = None,
                 callee_map: Dict[str, Set[str]] = None):
        """
        Initialize mock pointer results.
        
        Args:
            precise: Whether to provide precise results (False = always over-approximate)
            singleton_vars: Set of variables that are singletons
            alias_pairs: Set of variable pairs that may alias
            callee_map: Mapping from call site IDs to possible callee names
        """
        self.precise = precise
        self.singleton_vars = singleton_vars or set()
        self.alias_pairs = alias_pairs or set()
        self.callee_map = callee_map or {}
        self._digest_version = "mock-v1.0"
    
    def possible_callees(self, call_site: CallSite, ctx: Optional[Context] = None) -> Set[FunctionSymbol]:
        if not self.precise:
            # Over-approximate: return all possible functions
            return {MockFunctionSymbol("unknown_function")}
        
        callees = self.callee_map.get(call_site.site_id, set())
        return {MockFunctionSymbol(name) for name in callees}
    
    def points_to(self, var: str, ctx: Optional[Context] = None) -> PointsToSet:
        return MockPointsToSet([MockAbstractObject(f"obj_{var}")])
    
    def field_points_to(self, obj: AbstractObject, field: FieldKey) -> PointsToSet:
        return MockPointsToSet([MockAbstractObject(f"field_{obj.alloc_id}_{field.kind}")])
    
    def may_alias(self, a_var: str, b_var: str, ctx: Optional[Context] = None) -> bool:
        if not self.precise:
            return True  # Over-approximate
        
        return (a_var, b_var) in self.alias_pairs or (b_var, a_var) in self.alias_pairs
    
    def is_singleton(self, target: Any, ctx: Optional[Context] = None) -> bool:
        if not self.precise:
            return False  # Under-approximate
        
        if isinstance(target, str):
            return target in self.singleton_vars
        return False
    
    def call_graph_successors(self, fn: FunctionSymbol) -> Set[FunctionSymbol]:
        # Simple mock: each function can call any other function
        return {MockFunctionSymbol("successor")}
    
    def pointer_digest_version(self) -> str:
        return self._digest_version


class MockFunctionSymbol:
    """Mock implementation of FunctionSymbol."""
    
    def __init__(self, name: str):
        self.name = name
    
    def __str__(self) -> str:
        return self.name
    
    def __eq__(self, other) -> bool:
        return isinstance(other, MockFunctionSymbol) and self.name == other.name
    
    def __hash__(self) -> int:
        return hash(self.name)


class MockCallSite:
    """Mock implementation of CallSite."""
    
    def __init__(self, site_id: str, filename: str = "test.py", line: int = 1, col: int = 0):
        self.site_id = site_id
        self.filename = filename
        self.line = line
        self.col = col
    
    def __str__(self) -> str:
        return f"{self.filename}:{self.line}:{self.col}"


class MockAbstractObject:
    """Mock implementation of AbstractObject."""
    
    def __init__(self, alloc_id: str):
        self.alloc_id = alloc_id
    
    def __str__(self) -> str:
        return self.alloc_id
    
    def __eq__(self, other) -> bool:
        return isinstance(other, MockAbstractObject) and self.alloc_id == other.alloc_id
    
    def __hash__(self) -> int:
        return hash(self.alloc_id)


class MockPointsToSet:
    """Mock implementation of PointsToSet."""
    
    def __init__(self, objects: Iterable[AbstractObject]):
        self._objects = list(objects)
    
    def __iter__(self) -> Iterable[AbstractObject]:
        return iter(self._objects)
    
    def __len__(self) -> int:
        return len(self._objects)
    
    def __bool__(self) -> bool:
        return len(self._objects) > 0


class MockContext:
    """Mock implementation of Context."""
    
    def __init__(self, call_string: Tuple[CallSite, ...] = ()):
        self.call_string = call_string
    
    def __str__(self) -> str:
        return " -> ".join(str(cs) for cs in self.call_string)
