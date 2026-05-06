"""
Contract schema for unknown calls.

Contracts represent over-approximating relations R_f ⊆ In × Out for
unknown function calls, ensuring soundness: Sem_f ⊆ R_f.
"""

from dataclasses import dataclass
from typing import Optional, Set, List


@dataclass
class HeapEffect:
    """
    Heap footprint specification for a contract.
    
    Over-approximates what heap locations may be read/written/allocated.
    """
    may_read: Set[str]  # Heap locations that may be read
    may_write: Set[str]  # Heap locations that may be mutated
    may_allocate: bool  # Whether new objects may be allocated
    
    @staticmethod
    def havoc() -> 'HeapEffect':
        """
        Maximum over-approximation: arbitrary heap effects.
        This is the sound default for completely unknown calls.
        """
        return HeapEffect(
            may_read={'*'},  # May read anything
            may_write={'*'},  # May write anything
            may_allocate=True
        )
    
    @staticmethod
    def pure() -> 'HeapEffect':
        """Pure function: no heap effects."""
        return HeapEffect(
            may_read=set(),
            may_write=set(),
            may_allocate=False
        )


@dataclass
class ExceptionEffect:
    """
    Exception behavior specification for a contract.
    
    Over-approximates which exceptions may be raised.
    """
    may_raise: Set[str]  # Exception types that may be raised
    always_raises: bool  # Whether the call always raises (never returns normally)
    domain_precondition: Optional[str] = None  # Human-readable precondition (e.g., "x >= 0")
    
    @staticmethod
    def havoc() -> 'ExceptionEffect':
        """
        Maximum over-approximation: may raise any exception.
        This is the sound default for completely unknown calls.
        """
        return ExceptionEffect(
            may_raise={'*'},  # May raise any exception
            always_raises=False
        )
    
    @staticmethod
    def no_raise() -> 'ExceptionEffect':
        """Function never raises exceptions."""
        return ExceptionEffect(
            may_raise=set(),
            always_raises=False
        )


@dataclass
class ValueConstraint:
    """
    Constraint on return value or argument.
    
    Expressed as Z3-checkable predicates where possible.
    """
    type_constraint: Optional[str] = None  # Expected type (None means unconstrained)
    range_constraint: Optional[tuple] = None  # (min, max) for numeric types
    predicate: Optional[str] = None  # Symbolic predicate expression


@dataclass
class Contract:
    """
    A contract for an unknown function call.
    
    Represents an over-approximating relation R_f where Sem_f ⊆ R_f.
    Must be sound: if actual behavior exceeds the contract, analyzer may be unsound.
    """
    function_name: str
    
    # Argument constraints (over-approximations)
    arg_constraints: List[ValueConstraint]
    
    # Return value constraints (over-approximations)
    return_constraint: ValueConstraint
    
    # Heap and exception effects
    heap_effect: HeapEffect
    exception_effect: ExceptionEffect
    
    # Provenance: how was this contract derived?
    # - "default": sound havoc default
    # - "stdlib_spec": from Python documentation/spec
    # - "source_analysis": analyzed callee source code
    # - "dse_validated": validated via dynamic symbolic execution
    provenance: str
    
    # Optional: symbolic relation as Z3 expression
    # This would encode the full R_f relation
    symbolic_relation: Optional[str] = None
    
    @staticmethod
    def havoc(function_name: str) -> 'Contract':
        """
        Sound default contract: maximal over-approximation.
        
        This contract makes no assumptions about the function's behavior,
        ensuring soundness for completely unknown calls.
        """
        return Contract(
            function_name=function_name,
            arg_constraints=[],
            return_constraint=ValueConstraint(),  # Unconstrained
            heap_effect=HeapEffect.havoc(),
            exception_effect=ExceptionEffect.havoc(),
            provenance="default"
        )
    
    def is_havoc(self) -> bool:
        """Check if this is the default havoc contract."""
        return (
            self.heap_effect.may_write == {'*'} and
            self.exception_effect.may_raise == {'*'}
        )


# Registry of known contracts
_contract_registry: dict[str, Contract] = {}


def register_contract(contract: Contract) -> None:
    """
    Register a contract for a known function.
    
    The contract must be an over-approximation (sound).
    """
    _contract_registry[contract.function_name] = contract


def get_contract(function_name: str) -> Contract:
    """
    Get the contract for a function.
    
    Returns the registered contract if available, otherwise returns
    the sound default havoc contract.
    
    Supports wildcard matching for method contracts:
    - Exact match takes precedence (e.g., "subprocess.Popen.communicate")
    - If no exact match, tries wildcard pattern (e.g., "*.communicate")
    
    Wildcard matching (iteration 280): Enables generic method contracts
    that apply to any object type (e.g., "*.decode" for bytes.decode, 
    bytearray.decode, etc.)
    """
    # Try exact match first
    if function_name in _contract_registry:
        return _contract_registry[function_name]
    
    # Try wildcard matching for methods (*.method_name)
    # Pattern: obj.method -> *.method
    if '.' in function_name:
        method_name = function_name.split('.')[-1]
        wildcard_pattern = f"*.{method_name}"
        if wildcard_pattern in _contract_registry:
            return _contract_registry[wildcard_pattern]
    
    # No match: return sound havoc default
    return Contract.havoc(function_name)


def list_contracts() -> List[str]:
    """List all registered contracts (excluding default havoc)."""
    return list(_contract_registry.keys())
