"""
Relational summaries for library calls (elevation plan implementation).

This module implements the "cases + fallback" summary format described in
ELEVATION_PLAN.md, enabling sound over-approximating relations R_f ⊆ In × Out
where Sem_f ⊆ R_f.

Key principles:
- Each summary has multiple guarded cases + a required havoc fallback
- Cases express symbolic constraints in Z3, not source patterns
- Heap observers (SeqLen, DictSize, etc.) enable structural reasoning
- Soundness: if no case guard holds, fallback must remain reachable
"""

from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Any
import z3
from enum import Enum

# Import from existing modules
from a3_python.z3model.values import SymbolicValue, ValueTag


class HeapObserver(Enum):
    """Heap property observers (symbolic functions over heap state)."""
    SEQ_LEN = "SeqLen"  # Length of list/tuple/str
    DICT_SIZE = "DictSize"  # Size of dict
    STR_LEN = "StrLen"  # Length of string (alias for SEQ_LEN for clarity)
    HAS_KEY = "HasKey"  # Whether dict has key


@dataclass
class RelationalCase:
    """
    One case in a relational summary: guard → post.
    
    A case represents a specific behavior mode of the function.
    If the guard holds, the postcondition constraints apply.
    """
    name: str  # Human-readable case name (for debugging)
    
    # Guard: (state, args) -> z3.BoolRef
    # Returns a Z3 boolean constraint that must hold for this case
    guard: Callable[..., z3.BoolRef]
    
    # Postcondition: (state, args, fresh_symbols) -> PostCondition
    # Returns constraints on return value, heap updates, path condition
    post: Callable[..., 'PostCondition']
    
    # May this case raise exceptions?
    may_raise: List[str] = field(default_factory=list)
    
    # Provenance: how was this case derived?
    provenance: str = "inferred"


@dataclass
class PostCondition:
    """
    Postcondition of a relational case.
    
    Expresses the effect of executing a call when a case's guard holds.
    """
    # Return value (symbolic)
    return_value: Optional[SymbolicValue] = None
    
    # Additional path constraints (conjuncted with path_condition)
    path_constraints: List[z3.BoolRef] = field(default_factory=list)
    
    # Heap updates (functional style: obj_id -> new properties)
    # For now, we'll express these as constraints rather than mutations
    heap_constraints: List[z3.BoolRef] = field(default_factory=list)
    
    # Observer updates (for heap observers like SeqLen)
    # Maps observer -> updates (will be handled by VM)
    observer_updates: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HavocCase:
    """
    Required fallback case: maximum over-approximation.
    
    This ensures soundness: if no specific case guard can be proven,
    the havoc fallback remains reachable, preventing unsound SAFE claims.
    """
    may_read_heap: bool = True
    may_write_heap: bool = True
    may_allocate: bool = True
    may_raise_any: bool = True
    
    def applies(self) -> bool:
        """Havoc always applies as the fallback."""
        return True


@dataclass
class RelationalSummary:
    """
    Complete relational summary for a function: cases + required fallback.
    
    This is the plug-in point for adding library semantics without
    modifying the VM. Each summary represents an over-approximating
    relation R_f where Sem_f ⊆ R_f.
    """
    function_id: str  # Stable identifier (e.g., "len", "math.sqrt")
    
    # Ordered list of specific cases (checked in order)
    cases: List[RelationalCase] = field(default_factory=list)
    
    # Required havoc fallback (always present for soundness)
    havoc: HavocCase = field(default_factory=HavocCase)
    
    # Provenance: how was this summary derived?
    provenance: str = "unknown"
    
    def add_case(self, case: RelationalCase) -> None:
        """Add a case to this summary (cases checked in order)."""
        self.cases.append(case)


# Registry of relational summaries
_summary_registry: Dict[str, RelationalSummary] = {}


def register_relational_summary(summary: RelationalSummary) -> None:
    """Register a relational summary for a function."""
    _summary_registry[summary.function_id] = summary


def get_relational_summary(function_id: str) -> Optional[RelationalSummary]:
    """Retrieve a registered relational summary."""
    return _summary_registry.get(function_id)


def has_relational_summary(function_id: str) -> bool:
    """Check if a relational summary exists for a function."""
    return function_id in _summary_registry


# Heap observer helpers (to be used in summary definitions)

def seq_len_observer(obj_id: z3.ExprRef) -> z3.ArithRef:
    """
    Create a SeqLen observer for an object.
    
    Returns a Z3 Int representing the length of a sequence (list/tuple/str).
    This is an uninterpreted function that will be constrained by the VM.
    """
    # For now, create a fresh symbolic integer with a stable name
    # The VM will need to track these and constrain them appropriately
    return z3.Int(f"SeqLen_{obj_id}")


def dict_size_observer(obj_id: z3.ExprRef) -> z3.ArithRef:
    """
    Create a DictSize observer for a dict object.
    
    Returns a Z3 Int representing the number of keys in the dict.
    """
    return z3.Int(f"DictSize_{obj_id}")


def has_key_observer(dict_id: z3.ExprRef, key: z3.ExprRef) -> z3.BoolRef:
    """
    Create a HasKey observer for a dict and key.
    
    Returns a Z3 Bool representing whether the dict contains the key.
    """
    # This would need to be an uninterpreted function in practice
    # For now, we return a fresh symbolic boolean
    return z3.Bool(f"HasKey_{dict_id}_{key}")
