"""
DOUBLE_FREE: Freeing the same resource or memory twice.

Unsafe region: machine state where a resource is freed/closed more than once,
potentially causing corruption or undefined behavior.

In Python (with GC), DOUBLE_FREE manifests as:
1. Closing the same file handle twice (second close on already-closed file)
2. Releasing the same lock/semaphore twice
3. Calling close()/free() on the same native extension object twice
4. Deallocating the same buffer/memoryview multiple times
5. Multiple explicit __del__ calls or resource cleanup

Unlike C/C++ where double-free can corrupt heap metadata, Python's reference
counting and GC prevent classic double-free memory corruption. However, resource
management double-free still manifests as semantic bugs:
- Close-on-closed operations that may raise exceptions
- Double-release of locks causing protocol violations
- Native object double-free leading to crashes

The semantic predicate checks for:
- Multiple close() calls on the same file/socket/resource
- Multiple release() calls on the same lock/semaphore
- Native extension double-free detection
"""

from typing import Optional
import z3


def is_unsafe_double_free(state) -> bool:
    """
    Unsafe predicate U_DOUBLE_FREE(σ).
    
    Returns True if the machine state σ shows a resource being freed/closed
    more than once:
    - double_free_reached flag set (indicating second free of same resource)
    - OR ValueError from closing already-closed file/socket
    - OR RuntimeError from double-release of lock
    - OR crash from native extension double-free
    
    The symbolic VM tracks resource lifecycle (allocated -> freed) and detects
    when a free operation targets an already-freed resource.
    
    Note: In Python, most double-free attempts are benign (close() on closed
    file is typically silent or raises ValueError). We detect the pattern
    rather than waiting for crash, as the bug exists even if currently benign.
    """
    # Check for explicit double-free flag
    if hasattr(state, 'double_free_reached') and state.double_free_reached:
        return True
    
    # Check for resource state tracking indicating double-free
    if hasattr(state, 'resource_states'):
        # Look for resources that have been freed multiple times
        for resource_id, lifecycle in state.resource_states.items():
            if hasattr(lifecycle, 'free_count') and lifecycle.free_count >= 2:
                return True
    
    # ValueError from closing already-closed file/socket
    # Note: Some Python operations are silent on double-close, so this
    # is not the only way to detect double-free
    if state.exception == "ValueError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if any(phrase in msg for phrase in [
                "closed file", 
                "i/o operation on closed",
                "closed socket"
            ]):
                return True
    
    # RuntimeError from double-release of synchronization primitives
    if state.exception == "RuntimeError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if any(phrase in msg for phrase in [
                "release unlocked lock",
                "cannot release",
                "already released"
            ]):
                return True
    
    # Crash from native extension double-free
    # (manifests as SystemError or segfault-like behavior)
    if state.exception == "SystemError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if "double free" in msg or "freed" in msg:
                return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for DOUBLE_FREE bug.
    
    Returns a dictionary with:
    - bug_type: "DOUBLE_FREE"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - resource_id: identifier of the double-freed resource
    - free_count: number of times resource was freed
    """
    resource_id = "unknown"
    free_count = 0
    resource_type = "unknown"
    
    if hasattr(state, 'double_free_reached') and state.double_free_reached:
        resource_id = getattr(state, 'double_freed_resource_id', resource_id)
        free_count = getattr(state, 'resource_free_count', 0)
        resource_type = getattr(state, 'double_freed_resource_type', resource_type)
    
    # Infer from resource_states if available
    if hasattr(state, 'resource_states'):
        for res_id, lifecycle in state.resource_states.items():
            if hasattr(lifecycle, 'free_count') and lifecycle.free_count >= 2:
                resource_id = res_id
                free_count = lifecycle.free_count
                resource_type = getattr(lifecycle, 'resource_type', resource_type)
                break
    
    # Infer from exception
    if hasattr(state, 'exception'):
        if state.exception == "ValueError":
            resource_type = "file_or_socket"
        elif state.exception == "RuntimeError":
            resource_type = "lock_or_semaphore"
        elif state.exception == "SystemError":
            resource_type = "native_object"
    
    return {
        "bug_type": "DOUBLE_FREE",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception if hasattr(state, 'exception') else None,
            "exception_message": str(getattr(state, 'exception_message', '')),
            "double_free_reached": getattr(state, 'double_free_reached', False),
            "resource_id": resource_id,
            "free_count": free_count,
            "resource_type": resource_type,
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
            "halted": state.halted if hasattr(state, 'halted') else False
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
