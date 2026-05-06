"""
USE_AFTER_FREE: Accessing memory or references that have been invalidated.

Unsafe region: machine state where a reference is used after the underlying
resource has been freed, deallocated, or invalidated.

In Python (with GC), USE_AFTER_FREE manifests as:
1. Using a closed file handle or socket (ValueError: I/O operation on closed file)
2. Accessing iterator after underlying collection was modified (RuntimeError)
3. Using weak references after referent was garbage collected
4. Calling methods on explicitly closed resources (database connections, etc.)
5. Native extension objects that manage C memory and have been freed

Unlike C/C++ where freed memory can be reused, Python's GC prevents classic
use-after-free. However, resource invalidation (file closure, weak ref death)
creates similar semantic bugs: using a reference to an invalidated resource.

The semantic predicate checks for operations on invalidated resources:
- Accessing closed file handles
- Using expired weak references
- Operations on explicitly freed native objects
"""

from typing import Optional
import z3


def is_unsafe_use_after_free(state) -> bool:
    """
    Unsafe predicate U_USE_AFTER_FREE(σ).
    
    Returns True if the machine state σ shows a reference being used
    after its underlying resource has been invalidated:
    - use_after_free_reached flag set (indicating invalidated resource access)
    - OR ValueError with "closed" in message (closed file/socket operations)
    - OR RuntimeError from accessing freed native object
    - OR ReferenceError from dereferencing dead weakref
    
    The symbolic VM tracks resource validity state and sets flags when
    operations attempt to use invalidated resources.
    
    Note: This is a Python-semantic interpretation. True USE_AFTER_FREE
    (dangling pointer dereference) occurs in native extensions; we detect
    the Python-level manifestation.
    """
    # Check for explicit use-after-free flag
    if hasattr(state, 'use_after_free_reached') and state.use_after_free_reached:
        return True
    
    # ValueError from closed file/socket
    if state.exception == "ValueError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if "closed" in msg or "i/o operation" in msg:
                return True
    
    # ReferenceError from dead weak reference
    if state.exception == "ReferenceError":
        return True
    
    # RuntimeError from freed native object
    if state.exception == "RuntimeError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if "freed" in msg or "invalid" in msg or "deallocated" in msg:
                return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for USE_AFTER_FREE bug.
    
    Returns a dictionary with:
    - bug_type: "USE_AFTER_FREE"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - resource_type: type of invalidated resource accessed
    """
    resource_type = "unknown"
    
    if hasattr(state, 'exception'):
        if state.exception == "ValueError":
            resource_type = "closed_file_or_socket"
        elif state.exception == "ReferenceError":
            resource_type = "dead_weakref"
        elif state.exception == "RuntimeError":
            resource_type = "freed_native_object"
    
    if hasattr(state, 'use_after_free_reached') and state.use_after_free_reached:
        resource_type = getattr(state, 'invalidated_resource_type', resource_type)
    
    return {
        "bug_type": "USE_AFTER_FREE",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception if hasattr(state, 'exception') else None,
            "exception_message": str(getattr(state, 'exception_message', '')),
            "use_after_free_reached": getattr(state, 'use_after_free_reached', False),
            "resource_type": resource_type,
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
            "halted": state.halted if hasattr(state, 'halted') else False
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
