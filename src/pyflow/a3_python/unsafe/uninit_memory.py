"""
UNINIT_MEMORY: Reading from uninitialized memory locations.

Unsafe region: machine state where a read operation accesses memory that
has not been properly initialized, leading to undefined or unpredictable values.

In Python (with managed memory), UNINIT_MEMORY manifests as:
1. Reading from uninitialized native buffers (ctypes, array.array, bytearray)
2. Accessing uninitialized memory allocated by C extensions
3. Using memoryview or buffer objects before initialization
4. Reading from unallocated/uninitialized struct.pack buffers
5. Accessing __slots__ before assignment
6. Reading from mmap'd memory before writing

Unlike C/C++ where uninitialized memory contains arbitrary garbage, Python's
managed types are initialized by default. However, native extensions, buffer
protocols, and low-level interfaces can expose uninitialized memory:
- ctypes.create_string_buffer() creates uninitialized bytes
- array.array() may have uninitialized elements
- memoryview of uninitialized buffers
- Native extension memory before initialization

The semantic predicate checks for:
- Reads from buffers marked as uninitialized
- Access to __slots__ attributes before assignment (AttributeError)
- Native buffer operations before proper initialization
- Use of memory views over uninitialized regions
"""

from typing import Optional
import z3


def is_unsafe_uninit_memory(state) -> bool:
    """
    Unsafe predicate U_UNINIT_MEMORY(σ).
    
    Returns True if the machine state σ shows a read from uninitialized memory:
    - uninit_memory_reached flag set (indicating uninitialized memory access)
    - OR UnboundLocalError (variable used before assignment)
    - OR NameError (variable not defined at all)
    - OR AttributeError from accessing uninitialized __slots__
    - OR ValueError from operating on uninitialized buffer
    - OR uninitialized buffer read tracked by symbolic VM
    
    The symbolic VM tracks buffer/memory initialization state and detects
    when read operations target uninitialized regions.
    
    Note: In Python, uninitialized variable access maps to UnboundLocalError
    (for locals) or NameError (for globals/names). These are the Python
    equivalent of uninitialized memory reads in C/C++.
    """
    # Check if catch guard is established (exception caught by handler)
    if hasattr(state, 'has_catch_guard'):
        exc = getattr(state, 'exception', None)
        if exc and state.has_catch_guard(exc):
            return False
    
    # Check for explicit uninitialized memory flag
    if hasattr(state, 'uninit_memory_reached') and state.uninit_memory_reached:
        return True
    
    # UnboundLocalError: variable used before assignment in local scope
    # This is the Python equivalent of reading uninitialized memory
    if state.exception == "UnboundLocalError":
        return True
    
    # NameError: variable not defined (similar to uninitialized read)
    if state.exception == "NameError":
        return True
    
    # Check for buffer states tracking uninitialized reads
    if hasattr(state, 'buffer_states'):
        for buffer_id, buf_state in state.buffer_states.items():
            if hasattr(buf_state, 'uninitialized_read') and buf_state.uninitialized_read:
                return True
    
    # AttributeError from accessing uninitialized __slots__
    # (slot exists but was never assigned)
    if state.exception == "AttributeError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            # Distinguish from missing attribute vs uninitialized slot
            if "slot" in msg or ("has no attribute" in msg and hasattr(state, 'is_slot_access')):
                return True
    
    # ValueError from operating on uninitialized buffer
    # Some operations detect uninitialized state and raise
    if state.exception == "ValueError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if any(phrase in msg for phrase in [
                "uninitialized",
                "not initialized",
                "buffer not ready",
                "invalid buffer"
            ]):
                return True
    
    # SystemError from native extension reading uninitialized memory
    if state.exception == "SystemError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if "uninitialized" in msg or "uninit" in msg:
                return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for UNINIT_MEMORY bug.
    
    Returns a dictionary with:
    - bug_type: "UNINIT_MEMORY"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - buffer_id: identifier of the uninitialized buffer accessed
    - access_type: type of access (read, use, etc.)
    """
    buffer_id = "unknown"
    access_type = "read"
    buffer_type = "unknown"
    
    if hasattr(state, 'uninit_memory_reached') and state.uninit_memory_reached:
        buffer_id = getattr(state, 'uninit_buffer_id', buffer_id)
        access_type = getattr(state, 'uninit_access_type', access_type)
        buffer_type = getattr(state, 'uninit_buffer_type', buffer_type)
    
    # Infer from buffer_states if available
    if hasattr(state, 'buffer_states'):
        for buf_id, buf_state in state.buffer_states.items():
            if hasattr(buf_state, 'uninitialized_read') and buf_state.uninitialized_read:
                buffer_id = buf_id
                buffer_type = getattr(buf_state, 'buffer_type', buffer_type)
                access_type = getattr(buf_state, 'access_type', access_type)
                break
    
    # Infer from exception
    if hasattr(state, 'exception'):
        if state.exception == "AttributeError":
            buffer_type = "slot_attribute"
            access_type = "attribute_access"
        elif state.exception == "ValueError":
            buffer_type = "native_buffer"
        elif state.exception == "SystemError":
            buffer_type = "native_extension_memory"
    
    return {
        "bug_type": "UNINIT_MEMORY",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception if hasattr(state, 'exception') else None,
            "exception_message": str(getattr(state, 'exception_message', '')),
            "uninit_memory_reached": getattr(state, 'uninit_memory_reached', False),
            "buffer_id": buffer_id,
            "buffer_type": buffer_type,
            "access_type": access_type,
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
            "halted": state.halted if hasattr(state, 'halted') else False
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
