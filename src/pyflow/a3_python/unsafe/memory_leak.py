"""
MEMORY_LEAK: Unbounded heap growth or unreachable resource retention.

Unsafe region: machine state where heap size grows unboundedly
(typically in a loop) without any corresponding deallocation or upper bound.

In Python (with GC), "memory leak" means:
1. Unbounded heap growth: allocating objects without an upper bound on heap size
2. Resource retention: holding references to objects that will never be accessed again

This is distinct from C/Rust memory leaks (no GC). For Python, we focus on:
- Unbounded accumulation (e.g., appending to a list in an infinite loop)
- Resource handle leaks (file handles, sockets) that aren't released

The semantic predicate checks for evidence of unbounded growth:
- Heap size exceeding a reasonable threshold
- Loop iterations with monotonically increasing heap
- Resource handle count exceeding limits

Note: This requires tracking heap allocation over paths. Conservative detection
may use heuristics (allocation in loops without bounds), but must still be grounded
in the heap model.
"""

from typing import Optional
import z3


def is_unsafe_memory_leak(state) -> bool:
    """
    Unsafe predicate U_MEMORY_LEAK(σ).
    
    Returns True if the machine state σ exhibits unbounded heap growth:
    - heap_size_unbounded flag set (indicating unbounded allocation pattern detected)
    - OR resource_leak_detected flag set (indicating resource handle exhaustion)
    - OR heap size exceeds configured maximum threshold
    
    The symbolic VM tracks allocation patterns during loop unrolling and
    sets these flags when unbounded growth is detected.
    
    Note: This is a conservative approximation. True unbounded growth requires
    proving that heap size → ∞ along all paths, which requires ranking functions
    (NON_TERMINATION analysis). We start with bounded detection.
    """
    # Check for explicit heap growth flags
    if hasattr(state, 'heap_size_unbounded') and state.heap_size_unbounded:
        return True
    
    if hasattr(state, 'resource_leak_detected') and state.resource_leak_detected:
        return True
    
    # Check heap size against threshold (if heap model supports size tracking)
    if hasattr(state, 'heap') and hasattr(state.heap, 'size'):
        # Conservative threshold: 10000 objects in heap
        # (This is a bounded approximation; true unboundedness requires proof)
        if state.heap.size() > 10000:
            return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for MEMORY_LEAK bug.
    
    Returns a dictionary with:
    - bug_type: "MEMORY_LEAK"
    - trace: list of executed instructions
    - final_state: description of the unsafe state (heap size, growth pattern)
    - path_condition: the Z3 path constraint (if available)
    - leak_type: "unbounded_growth" or "resource_leak"
    """
    leak_type = "unknown"
    heap_size = None
    
    if hasattr(state, 'heap_size_unbounded') and state.heap_size_unbounded:
        leak_type = "unbounded_growth"
    
    if hasattr(state, 'resource_leak_detected') and state.resource_leak_detected:
        leak_type = "resource_leak"
    
    if hasattr(state, 'heap') and hasattr(state.heap, 'size'):
        heap_size = state.heap.size()
        if heap_size > 10000:
            leak_type = "heap_size_threshold_exceeded"
    
    return {
        "bug_type": "MEMORY_LEAK",
        "trace": path_trace,
        "final_state": {
            "leak_type": leak_type,
            "heap_size": heap_size,
            "heap_size_unbounded": getattr(state, 'heap_size_unbounded', False),
            "resource_leak_detected": getattr(state, 'resource_leak_detected', False),
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
            "halted": state.halted if hasattr(state, 'halted') else False
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
