"""
SEND_SYNC: Thread-safety contract violation (cross-thread use / reentrancy violations).

Unsafe region: machine state where thread-safety invariants are violated.

In Rust, Send/Sync are marker traits controlling thread safety:
- Send: safe to transfer ownership across threads
- Sync: safe to share references across threads

Python adaptation (SEND_SYNC as thread-safety contract violation):

1. **Non-thread-safe object used across threads**:
   - Objects documented as not thread-safe (e.g., sqlite3.Connection, io.IOBase)
   - Used from multiple threads without synchronization
   - Violation: cross-thread use without protection

2. **Reentrancy violations**:
   - Non-reentrant functions/objects called recursively (signal handlers, __del__)
   - GIL-release operations that assume single-threaded context
   - Thread-local storage violations (accessing TLS from wrong thread)

3. **Iterator/generator protocol violations across threads**:
   - Iterator created in one thread, consumed in another
   - Generator send/throw from wrong thread
   - Violation of "iterators are not thread-safe" invariant

4. **C extension thread-safety violations**:
   - Objects with thread affinity (must be used from creating thread)
   - Numpy arrays with OWNDATA flag accessed without GIL
   - Thread-unsafe C extension state

5. **Reference counting violations at boundary**:
   - Py_DECREF from wrong thread (without GIL)
   - Reference count manipulation in signal handler
   - Resurrection in finalizer causing cross-thread visibility

Semantic predicate:
- Object with thread-safety contract used from wrong thread
- Object marked non-reentrant called recursively
- Thread-local storage accessed from wrong thread  
- Iterator/generator used from different thread than creator
- Explicit violation flag from symbolic VM tracking thread affinity

Contrast with DATA_RACE:
- DATA_RACE: concurrent conflicting accesses to shared memory
- SEND_SYNC: violation of thread-safety contract (may not race but violates protocol)
- Example: using sqlite3.Connection from two threads sequentially (no race) still violates thread-safety

Contrast with DEADLOCK:
- DEADLOCK: circular wait preventing progress
- SEND_SYNC: wrong-thread use or reentrancy violation (may not block)
"""

from typing import Optional, Dict, Set
import z3


def is_unsafe_send_sync(state) -> bool:
    """
    Unsafe predicate U_SEND_SYNC(σ).
    
    Returns True if machine state σ shows a thread-safety contract violation:
    - Object with thread affinity accessed from wrong thread
    - Non-reentrant operation called recursively
    - Thread-local storage violation
    - Iterator/generator cross-thread use
    - Explicit send_sync_violation flag from symbolic VM
    
    The symbolic VM tracks:
    1. Per-object thread affinity (created_by_thread, allowed_threads)
    2. Per-function reentrancy state (in_call_stack, reentrant=False)
    3. Thread-local storage mappings (thread_id -> TLS objects)
    4. Iterator/generator ownership (iterator_id -> owning_thread)
    5. Call stack depth for reentrancy detection
    
    Detection strategies:
    
    1. Thread affinity violation:
       - Object O has thread affinity T1
       - Current thread T2 != T1 accesses O
       - No synchronization primitive used
       - => SEND_SYNC violation
    
    2. Reentrancy violation:
       - Function F marked non-reentrant (signal handler, finalizer)
       - F appears multiple times in call stack
       - => SEND_SYNC violation
    
    3. Thread-local storage violation:
       - Thread T2 accesses TLS object owned by thread T1
       - => SEND_SYNC violation
    
    4. Iterator cross-thread use:
       - Iterator created in thread T1
       - next() called from thread T2
       - => SEND_SYNC violation (iterators not thread-safe)
    """
    # Explicit thread-safety violation flag
    if hasattr(state, 'send_sync_violation') and state.send_sync_violation:
        return True
    
    # Thread affinity violation check
    if hasattr(state, 'thread_affinity_violations') and state.thread_affinity_violations:
        return True
    
    # Check for thread affinity in accessed objects
    if hasattr(state, 'current_thread_id') and hasattr(state, 'heap'):
        current_thread = state.current_thread_id
        
        # Check recently accessed objects for thread affinity violations
        if hasattr(state, 'last_heap_access'):
            obj_id = state.last_heap_access.get('object_id')
            if obj_id and obj_id in state.heap:
                obj = state.heap[obj_id]
                if hasattr(obj, 'thread_affinity'):
                    affinity_thread = obj.thread_affinity
                    if affinity_thread is not None and affinity_thread != current_thread:
                        # Object with thread affinity accessed from wrong thread
                        return True
    
    # Reentrancy violation check
    if hasattr(state, 'reentrancy_violation') and state.reentrancy_violation:
        return True
    
    # Check call stack for non-reentrant functions called recursively
    if hasattr(state, 'frame_stack') and len(state.frame_stack) > 0:
        # Track function IDs in call stack
        function_ids = []
        non_reentrant_funcs = set()
        
        for frame in state.frame_stack:
            func_id = getattr(frame, 'function_id', None)
            if func_id:
                function_ids.append(func_id)
                # Check if function is marked non-reentrant
                if hasattr(frame, 'non_reentrant') and frame.non_reentrant:
                    non_reentrant_funcs.add(func_id)
        
        # Reentrancy violation: non-reentrant function appears multiple times
        for func_id in non_reentrant_funcs:
            if function_ids.count(func_id) > 1:
                return True
    
    # Thread-local storage violation
    if hasattr(state, 'tls_violation') and state.tls_violation:
        return True
    
    # Check TLS access violations
    if hasattr(state, 'tls_map') and hasattr(state, 'current_thread_id'):
        current_thread = state.current_thread_id
        # If last TLS access was to wrong thread's storage
        if hasattr(state, 'last_tls_access'):
            tls_owner = state.last_tls_access.get('owner_thread')
            if tls_owner is not None and tls_owner != current_thread:
                return True
    
    # Iterator cross-thread violation
    if hasattr(state, 'iterator_cross_thread_violation') and state.iterator_cross_thread_violation:
        return True
    
    # Check iterator ownership
    if hasattr(state, 'iterator_ownership') and hasattr(state, 'current_thread_id'):
        current_thread = state.current_thread_id
        # If last iterator access was from wrong thread
        if hasattr(state, 'last_iterator_access'):
            iterator_id = state.last_iterator_access.get('iterator_id')
            if iterator_id and iterator_id in state.iterator_ownership:
                owner_thread = state.iterator_ownership[iterator_id]
                if owner_thread != current_thread:
                    return True
    
    # Exception patterns indicating thread-safety violations
    if hasattr(state, 'exception'):
        exc = state.exception
        # RuntimeError from thread-safety violations
        if exc == "RuntimeError":
            # Check exception message if available
            if hasattr(state, 'exception_msg'):
                msg = state.exception_msg.lower()
                if any(pattern in msg for pattern in [
                    'thread',
                    'reentrant',
                    'wrong thread',
                    'thread affinity',
                    'thread-local',
                    'not thread-safe'
                ]):
                    return True
        
        # sqlite3.ProgrammingError: check from wrong thread
        if exc == "ProgrammingError":
            if hasattr(state, 'exception_msg'):
                msg = state.exception_msg.lower()
                if 'thread' in msg or 'check_same_thread' in msg:
                    return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for SEND_SYNC bug.
    
    Returns a dictionary with:
    - bug_type: "SEND_SYNC"
    - violation_kind: specific kind of violation
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - thread_info: thread IDs and affinity information
    - path_condition: the Z3 path constraint (if available)
    """
    violation_kind = "unknown"
    thread_info = {}
    
    # Determine specific violation kind
    if hasattr(state, 'send_sync_violation') and state.send_sync_violation:
        violation_kind = "explicit_flag"
    elif hasattr(state, 'thread_affinity_violations') and state.thread_affinity_violations:
        violation_kind = "thread_affinity"
        thread_info['violations'] = state.thread_affinity_violations
    elif hasattr(state, 'reentrancy_violation') and state.reentrancy_violation:
        violation_kind = "reentrancy"
    elif hasattr(state, 'tls_violation') and state.tls_violation:
        violation_kind = "thread_local_storage"
    elif hasattr(state, 'iterator_cross_thread_violation') and state.iterator_cross_thread_violation:
        violation_kind = "iterator_cross_thread"
    
    # Collect thread information
    if hasattr(state, 'current_thread_id'):
        thread_info['current_thread'] = state.current_thread_id
    
    if hasattr(state, 'all_thread_ids'):
        thread_info['all_threads'] = list(state.all_thread_ids)
    
    # Object affinity info
    if hasattr(state, 'last_heap_access'):
        obj_id = state.last_heap_access.get('object_id')
        if obj_id and hasattr(state, 'heap') and obj_id in state.heap:
            obj = state.heap[obj_id]
            if hasattr(obj, 'thread_affinity'):
                thread_info['object_affinity'] = {
                    'object_id': obj_id,
                    'affinity_thread': obj.thread_affinity
                }
    
    # Reentrancy info
    if hasattr(state, 'frame_stack'):
        frame_info = []
        for idx, frame in enumerate(state.frame_stack):
            func_id = getattr(frame, 'function_id', f'frame_{idx}')
            non_reentrant = getattr(frame, 'non_reentrant', False)
            frame_info.append({
                'function_id': func_id,
                'non_reentrant': non_reentrant
            })
        thread_info['call_stack'] = frame_info
    
    # TLS info
    if hasattr(state, 'last_tls_access'):
        thread_info['tls_access'] = state.last_tls_access
    
    # Iterator info
    if hasattr(state, 'last_iterator_access'):
        thread_info['iterator_access'] = state.last_iterator_access
    
    return {
        "bug_type": "SEND_SYNC",
        "violation_kind": violation_kind,
        "trace": path_trace,
        "final_state": {
            "exception": getattr(state, 'exception', None),
            "exception_msg": getattr(state, 'exception_msg', None),
            "send_sync_violation": getattr(state, 'send_sync_violation', False),
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
            "halted": state.halted
        },
        "thread_info": thread_info,
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
