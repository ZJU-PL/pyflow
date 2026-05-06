"""
ITERATOR_INVALID: Collection mutation invalidation during iteration.

Unsafe region: machine state where a collection is modified during iteration,
causing iterator invalidation. In Python this manifests as:
- RuntimeError("dictionary changed size during iteration")
- RuntimeError("set changed size during iteration")
- Undefined behavior for list iteration with concurrent modification

This is a pure Python semantics bug class. Iterator invalidation includes:
- Dict/set mutation (add/remove keys) during iteration (raises RuntimeError)
- List mutation during iteration (undefined behavior, may skip/repeat elements)

The semantic unsafe predicate is: "an iterator is active on collection C,
and C is mutated (structural change) before the iterator completes/is discarded."
"""

from typing import Optional
import z3


def is_unsafe_iterator_invalid(state) -> bool:
    """
    Unsafe predicate U_ITERATOR_INVALID(σ).
    
    Returns True if the machine state σ has:
    - iterator_invalidation_reached flag set to True, indicating a collection
      was mutated during active iteration
    - OR exception is "RuntimeError" with evidence of iterator invalidation
    
    Note: The symbolic VM tracks active iterators (in-progress iteration
    contexts) and collection mutation operations. When a mutation occurs
    on a collection with an active iterator, iterator_invalidation_reached
    is set to True.
    
    In concrete Python execution, this manifests as:
    - RuntimeError for dict/set: "dictionary changed size during iteration"
    - Silent bugs for list: may skip elements or iterate incorrectly
    """
    if hasattr(state, 'iterator_invalidation_reached') and state.iterator_invalidation_reached:
        return True
    
    # RuntimeError might be iterator invalidation
    # (but could also be other things - the flag is more precise)
    if state.exception == "RuntimeError":
        # Check if we have evidence this is specifically iterator invalidation
        if hasattr(state, 'iterator_invalidation_reached'):
            return state.iterator_invalidation_reached
        # Without the flag, we can't be certain - this might be other RuntimeError
        # Conservative: only report if we have the semantic flag
        return False
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for ITERATOR_INVALID bug.
    
    Returns a dictionary with:
    - bug_type: "ITERATOR_INVALID"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    """
    return {
        "bug_type": "ITERATOR_INVALID",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "iterator_invalidation_reached": getattr(state, 'iterator_invalidation_reached', False),
            "active_iterators": getattr(state, 'active_iterators', []),
            "last_mutation": getattr(state, 'last_collection_mutation', None),
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
