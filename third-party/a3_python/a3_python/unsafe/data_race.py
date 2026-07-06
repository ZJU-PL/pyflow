"""
DATA_RACE: Concurrent unsynchronized access to shared state with at least one write.

Unsafe region: machine state where multiple threads access the same memory location
concurrently, with at least one write access, without proper synchronization.

In Python (with GIL), DATA_RACE is subtle:
1. **GIL protects most pure-Python operations** - they are atomic at bytecode level
2. **Races can occur when GIL is released**:
   - I/O operations (network, disk, blocking calls)
   - C extensions that release GIL
   - Numpy/scientific computing operations
   - Threading primitives themselves
3. **Common Python data race patterns**:
   - Multiple threads writing to shared dict/list without locks
   - Check-then-act patterns (TOCTOU on shared state)
   - Compound operations split across GIL releases
   - Race on reference counts in C extensions
4. **Non-atomic compound operations**:
   - x += 1 (LOAD, ADD, STORE - can interleave)
   - list.append in tight loop (internal resize can race)
   - dict mutations from multiple threads

The semantic predicate checks for:
- Concurrent access to shared heap locations by multiple threads
- At least one access is a write
- No synchronization primitive (lock) protecting the access
- Detection via:
  - Lockset algorithm (Eraser-style): track locks held at each access
  - Happens-before violation: concurrent accesses without ordering
  - GIL-release boundary analysis: operations that can interleave
"""

from typing import Optional
import z3


def is_unsafe_data_race(state) -> bool:
    """
    Unsafe predicate U_DATA_RACE(σ).
    
    Returns True if the machine state σ shows a data race:
    - data_race_reached flag set (indicating race detected by lockset algorithm)
    - OR concurrent unprotected access to shared location (tracked in heap access log)
    - OR check-then-act pattern on shared state without synchronization
    - OR exception indicating race manifestation (RuntimeError: dictionary changed size)
    
    The symbolic VM tracks:
    1. Per-thread locksets (what locks are held)
    2. Per-heap-location access history (thread_id, is_write, lockset, timestamp)
    3. Happens-before relations between threads
    
    Race detection (Lockset / Eraser algorithm):
    - For each heap location L, maintain lockset C(L) = locks held by ALL threads accessing L
    - Start with C(L) = all_locks
    - On access by thread T with lockset LS_T: C(L) = C(L) ∩ LS_T
    - If C(L) becomes empty AND there's a write: DATA_RACE
    
    Happens-before violation:
    - Two accesses a1, a2 to same location
    - At least one is write
    - NOT(a1 happens-before a2) AND NOT(a2 happens-before a1)
    - => RACE
    
    Note: The GIL makes this subtle. We detect races that:
    1. Actually manifest (exception from concurrent dict mutation)
    2. Would manifest if GIL is released (modeled operations in C extensions)
    3. Violate lockset discipline (no lock held across shared access)
    """
    # Explicit data race flag set by symbolic VM
    if hasattr(state, 'data_race_reached') and state.data_race_reached:
        return True
    
    # Check lockset algorithm result
    if hasattr(state, 'heap_access_log'):
        # Analyze access log for races
        location_accesses = {}  # location -> [(thread, is_write, lockset, timestamp)]
        
        for access in state.heap_access_log:
            loc = access.get('location')
            if loc not in location_accesses:
                location_accesses[loc] = []
            location_accesses[loc].append(access)
        
        # Check each location for race condition
        for loc, accesses in location_accesses.items():
            if len(accesses) < 2:
                continue
            
            # Compute intersection of locksets (Eraser algorithm)
            common_lockset = None
            has_write = False
            threads = set()
            
            for access in accesses:
                threads.add(access.get('thread_id'))
                if access.get('is_write'):
                    has_write = True
                
                lockset = set(access.get('lockset', []))
                if common_lockset is None:
                    common_lockset = lockset
                else:
                    common_lockset = common_lockset.intersection(lockset)
            
            # Race if: multiple threads, at least one write, empty common lockset
            # The lockset algorithm (Eraser) says: if common lockset is non-empty,
            # there is no race (the lock provides ordering)
            if len(threads) >= 2 and has_write and len(common_lockset) == 0:
                # No common lock protection - now check happens-before
                # (maybe there's synchronization via other means)
                for i, access1 in enumerate(accesses):
                    for access2 in accesses[i+1:]:
                        if access1['thread_id'] != access2['thread_id']:
                            # Different threads - check ordering
                            if not _happens_before(access1, access2, state) and \
                               not _happens_before(access2, access1, state):
                                # No ordering: concurrent access
                                if access1.get('is_write') or access2.get('is_write'):
                                    return True
    
    # RuntimeError from concurrent dict/set modification
    if state.exception == "RuntimeError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if any(phrase in msg for phrase in [
                "dictionary changed size during iteration",
                "set changed size during iteration",
                "dictionary keys changed during iteration"
            ]):
                return True
    
    # ValueError from concurrent list modification patterns
    if state.exception == "ValueError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if "concurrent" in msg or "race" in msg:
                return True
    
    # Check for TOCTOU (Time-Of-Check-Time-Of-Use) patterns
    if hasattr(state, 'toctou_race_detected') and state.toctou_race_detected:
        return True
    
    # Check thread-safety violation tracking
    if hasattr(state, 'thread_safety_violation') and state.thread_safety_violation:
        return True
    
    return False


def _happens_before(access1: dict, access2: dict, state) -> bool:
    """
    Check if access1 happens-before access2.
    
    Happens-before holds if:
    - They're in the same thread and access1's timestamp < access2's timestamp
    - There's a synchronization edge (lock release -> acquire, thread join, etc.)
    - Transitivity of happens-before relation
    """
    # Same thread: use timestamp ordering
    if access1.get('thread_id') == access2.get('thread_id'):
        return access1.get('timestamp', 0) < access2.get('timestamp', 0)
    
    # Different threads: check for synchronization edges
    if hasattr(state, 'happens_before_edges'):
        # Check if there's a path in happens-before graph
        # from (thread1, timestamp1) to (thread2, timestamp2)
        # This is a transitive closure check
        # Simplified: direct edge check
        edge = (
            (access1['thread_id'], access1.get('timestamp')),
            (access2['thread_id'], access2.get('timestamp'))
        )
        if edge in state.happens_before_edges:
            return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for DATA_RACE bug.
    
    Returns a dictionary with:
    - bug_type: "DATA_RACE"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - racing_threads: thread IDs involved in the race
    - racing_location: heap location accessed without proper synchronization
    - access_pattern: description of conflicting accesses (read/write, locksets)
    """
    racing_threads = []
    racing_location = None
    access_pattern = []
    race_type = "unknown"
    
    # Extract race details from heap access log
    if hasattr(state, 'heap_access_log'):
        location_accesses = {}
        for access in state.heap_access_log:
            loc = access.get('location')
            if loc not in location_accesses:
                location_accesses[loc] = []
            location_accesses[loc].append(access)
        
        # Find the location with the race
        for loc, accesses in location_accesses.items():
            threads = set(a['thread_id'] for a in accesses)
            has_write = any(a.get('is_write') for a in accesses)
            
            if len(threads) >= 2 and has_write:
                # Compute common lockset
                common_lockset = None
                for access in accesses:
                    lockset = set(access.get('lockset', []))
                    if common_lockset is None:
                        common_lockset = lockset
                    else:
                        common_lockset = common_lockset.intersection(lockset)
                
                if common_lockset is not None and len(common_lockset) == 0:
                    racing_location = loc
                    racing_threads = sorted(threads)
                    access_pattern = [
                        {
                            'thread': a['thread_id'],
                            'operation': 'write' if a.get('is_write') else 'read',
                            'lockset': list(a.get('lockset', [])),
                            'timestamp': a.get('timestamp'),
                            'instruction': a.get('instruction')
                        }
                        for a in accesses
                    ]
                    race_type = "lockset_violation"
                    break
    
    # Infer from explicit flags
    if hasattr(state, 'data_race_reached') and state.data_race_reached:
        racing_location = getattr(state, 'racing_location', racing_location)
        racing_threads = getattr(state, 'racing_threads', racing_threads)
        race_type = getattr(state, 'race_type', race_type)
    
    # Infer from exceptions
    if hasattr(state, 'exception'):
        if state.exception == "RuntimeError":
            if hasattr(state, 'exception_message'):
                msg = str(state.exception_message).lower()
                if "dictionary changed size" in msg or "set changed size" in msg:
                    race_type = "concurrent_mutation_during_iteration"
    
    if hasattr(state, 'toctou_race_detected') and state.toctou_race_detected:
        race_type = "TOCTOU"
        racing_location = getattr(state, 'toctou_location', racing_location)
    
    return {
        "bug_type": "DATA_RACE",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception if hasattr(state, 'exception') else None,
            "exception_message": str(getattr(state, 'exception_message', '')),
            "data_race_reached": getattr(state, 'data_race_reached', False),
            "racing_threads": racing_threads,
            "racing_location": racing_location,
            "race_type": race_type,
            "access_pattern": access_pattern,
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
            "halted": state.halted if hasattr(state, 'halted') else False
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None,
        "analysis_method": "lockset_algorithm_and_happens_before"
    }
