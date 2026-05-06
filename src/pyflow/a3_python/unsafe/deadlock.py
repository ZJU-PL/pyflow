"""
DEADLOCK: Circular wait on synchronization primitives.

Unsafe region: machine state where threads are in a circular wait pattern,
each holding locks that others need, preventing forward progress.

Classic deadlock conditions (Coffman conditions):
1. Mutual exclusion: resources are held exclusively
2. Hold and wait: threads hold resources while waiting for others
3. No preemption: resources cannot be forcibly taken
4. Circular wait: cycle in resource dependency graph

Python deadlock scenarios:
1. **Lock ordering violations**:
   - Thread 1: acquire(A) -> acquire(B)
   - Thread 2: acquire(B) -> acquire(A)
   - => Potential deadlock

2. **Threading primitives deadlock**:
   - Lock/RLock circular wait
   - Condition variable wait with lock held
   - Semaphore exhaustion pattern
   - Queue.join() deadlock

3. **Async/await deadlock** (future):
   - Awaiting on circular coroutine dependencies
   - AsyncIO event loop deadlock

4. **Implicit deadlock patterns**:
   - Thread.join() on self or circular thread dependencies
   - Nested lock acquisition with inconsistent order
   - Deadlock via message passing (queue-based)

Detection strategies:
1. **Lock ordering graph**: track lock acquisition order per thread; detect cycles
2. **Resource allocation graph (RAG)**: model threads->locks edges (wait) and locks->threads (hold); detect cycles
3. **Static lock order analysis**: enforce total ordering on lock acquisitions
4. **Happens-before + circular wait**: combine temporal analysis with lock state

Semantic predicate:
- Circular wait detected in lock wait graph
- All threads in wait set are blocked (no forward progress possible)
- Deadlock manifest: threading.RLock.acquire timeout or threading deadlock exception
"""

from typing import Optional, Set, Dict, List, Tuple
import z3


def is_unsafe_deadlock(state) -> bool:
    """
    Unsafe predicate U_DEADLOCK(σ).
    
    Returns True if machine state σ shows a deadlock:
    - Circular wait detected in resource allocation graph
    - Multiple threads all blocked on lock acquisition
    - Lock ordering violation leading to deadlock
    - Thread.join() circular dependency
    - Explicit deadlock flag from symbolic VM
    
    The symbolic VM tracks:
    1. Per-thread lock acquisition order (stack of held locks)
    2. Per-thread wait state (waiting on which lock/resource)
    3. Lock wait graph: thread -> lock edges (wait), lock -> thread edges (hold)
    4. Lock ordering graph: captures order of acquisitions across program
    
    Deadlock detection algorithms:
    
    1. Resource Allocation Graph (RAG) cycle detection:
       - Nodes: threads T and locks L
       - Edges: T -> L (T waits for L), L -> T (T holds L)
       - Deadlock iff cycle exists in RAG
    
    2. Lock ordering violation:
       - Track global lock acquisition orders seen: (L1, L2) means L2 acquired after L1
       - If we see both (A, B) and (B, A) from different threads: potential deadlock
    
    3. All-threads-blocked state:
       - Every thread is in wait state (none runnable)
       - Each waiting on a resource held by another thread in the wait set
    """
    # Explicit deadlock flag
    if hasattr(state, 'deadlock_reached') and state.deadlock_reached:
        return True
    
    # Check for cycle in Resource Allocation Graph (RAG)
    if hasattr(state, 'lock_wait_graph'):
        if _has_cycle_in_rag(state.lock_wait_graph):
            return True
    
    # Check lock ordering violations
    if hasattr(state, 'lock_acquisition_orders'):
        if _detect_lock_ordering_violation(state.lock_acquisition_orders):
            return True
    
    # Check all-threads-blocked scenario
    if hasattr(state, 'threads') and hasattr(state, 'lock_holders'):
        if _all_threads_blocked(state.threads, state.lock_holders):
            return True
    
    # Thread.join() circular dependency
    if hasattr(state, 'thread_join_graph'):
        if _has_cycle_in_thread_graph(state.thread_join_graph):
            return True
    
    # Manifest deadlock: timeout on lock acquisition with known holder
    if hasattr(state, 'lock_acquire_timeout') and state.lock_acquire_timeout:
        # Lock acquire timed out - check if it's a true deadlock
        if hasattr(state, 'lock_holder') and state.lock_holder is not None:
            # Another thread holds the lock; check if that thread is waiting on us
            if _circular_wait_detected(state):
                return True
    
    # Exception patterns indicating deadlock
    if state.exception in ["DeadlockError", "threading.DeadlockError"]:
        return True
    
    # RuntimeError from reentrant lock misuse / potential deadlock
    if state.exception == "RuntimeError":
        if hasattr(state, 'exception_message'):
            msg = str(state.exception_message).lower()
            if any(phrase in msg for phrase in [
                "deadlock",
                "cannot acquire lock",
                "lock already held",
                "circular dependency"
            ]):
                return True
    
    return False


def _has_cycle_in_rag(wait_graph: dict) -> bool:
    """
    Detect cycle in Resource Allocation Graph.
    
    wait_graph structure:
    {
        'threads': {thread_id: {'waiting_on': lock_id or None, 'holding': [lock_ids]}},
        'locks': {lock_id: {'held_by': thread_id or None, 'waiters': [thread_ids]}}
    }
    
    Build directed graph and detect cycle via DFS.
    """
    if not wait_graph:
        return False
    
    threads = wait_graph.get('threads', {})
    locks = wait_graph.get('locks', {})
    
    # Build adjacency list: unified graph with both threads and locks as nodes
    # Edge types:
    #   thread -> lock (thread waits for lock)
    #   lock -> thread (lock held by thread)
    adj = {}
    
    # Add thread -> lock edges (waiting)
    for tid, tinfo in threads.items():
        if tid not in adj:
            adj[tid] = []
        waiting_on = tinfo.get('waiting_on')
        if waiting_on is not None:
            adj[tid].append(waiting_on)
    
    # Add lock -> thread edges (holding)
    for lid, linfo in locks.items():
        if lid not in adj:
            adj[lid] = []
        held_by = linfo.get('held_by')
        if held_by is not None:
            adj[lid].append(held_by)
    
    # DFS cycle detection
    visited = set()
    rec_stack = set()
    
    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True
            elif neighbor in rec_stack:
                # Back edge: cycle detected
                return True
        
        rec_stack.remove(node)
        return False
    
    # Check from all nodes (graph may be disconnected)
    for node in list(threads.keys()) + list(locks.keys()):
        if node not in visited:
            if dfs(node):
                return True
    
    return False


def _detect_lock_ordering_violation(acquisition_orders: list) -> bool:
    """
    Detect lock ordering violations (incompatible orders).
    
    acquisition_orders: list of (thread_id, lock_sequence) tuples
    Example:
    [
        ('T1', ['lockA', 'lockB']),  # T1 acquired A then B
        ('T2', ['lockB', 'lockA'])   # T2 acquired B then A => violation!
    ]
    
    For each pair of locks (L1, L2), check if we've seen:
    - Some thread acquire L1 before L2
    - Some other thread acquire L2 before L1
    This indicates potential deadlock (lock ordering violation).
    """
    if not acquisition_orders:
        return False
    
    # Build lock pairs: (lock1, lock2) means lock1 acquired before lock2
    seen_orders = {}  # (lock1, lock2) -> set of thread_ids that observed this order
    
    for thread_id, lock_seq in acquisition_orders:
        for i in range(len(lock_seq)):
            for j in range(i + 1, len(lock_seq)):
                lock1, lock2 = lock_seq[i], lock_seq[j]
                if lock1 == lock2:
                    continue  # Skip same lock (reentrant)
                
                pair = (lock1, lock2)
                if pair not in seen_orders:
                    seen_orders[pair] = set()
                seen_orders[pair].add(thread_id)
    
    # Check for conflicting orders
    for (lock1, lock2), threads in seen_orders.items():
        reverse_pair = (lock2, lock1)
        if reverse_pair in seen_orders:
            # Found conflicting order: some threads acquired lock1->lock2,
            # others acquired lock2->lock1
            # This is a lock ordering violation (potential deadlock)
            return True
    
    return False


def _all_threads_blocked(threads: dict, lock_holders: dict) -> bool:
    """
    Check if all threads are blocked in a circular wait.
    
    threads: {thread_id: {'state': 'running'|'waiting', 'waiting_on': lock_id}}
    lock_holders: {lock_id: thread_id}
    
    Deadlock if:
    - All threads are in 'waiting' state
    - Each waiting on a lock held by another thread in the wait set
    - Circular dependency exists
    """
    if not threads:
        return False
    
    # Check if any thread is runnable
    waiting_threads = {}
    for tid, tinfo in threads.items():
        if tinfo.get('state') == 'waiting':
            waiting_threads[tid] = tinfo.get('waiting_on')
        elif tinfo.get('state') == 'running':
            # At least one thread can make progress
            return False
    
    # All threads are waiting - check if circular
    if not waiting_threads:
        return False
    
    # Build wait graph: thread -> thread edges
    wait_edges = {}  # tid -> tid (waiting for)
    for tid, lock_id in waiting_threads.items():
        if lock_id and lock_id in lock_holders:
            holder = lock_holders[lock_id]
            if holder in waiting_threads:
                # This thread waits for a lock held by another waiting thread
                wait_edges[tid] = holder
    
    # Cycle detection in wait graph
    visited = set()
    rec_stack = set()
    
    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        
        if node in wait_edges:
            neighbor = wait_edges[node]
            if neighbor not in visited:
                if dfs(neighbor):
                    return True
            elif neighbor in rec_stack:
                return True
        
        rec_stack.remove(node)
        return False
    
    for tid in waiting_threads:
        if tid not in visited:
            if dfs(tid):
                return True
    
    return False


def _has_cycle_in_thread_graph(join_graph: dict) -> bool:
    """
    Detect cycle in thread join graph.
    
    join_graph: {thread_id: [thread_ids_waiting_to_join]}
    
    Example: {'T1': ['T2'], 'T2': ['T1']} => T1.join(T2) and T2.join(T1) => deadlock
    """
    if not join_graph:
        return False
    
    visited = set()
    rec_stack = set()
    
    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        
        for neighbor in join_graph.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True
            elif neighbor in rec_stack:
                return True
        
        rec_stack.remove(node)
        return False
    
    for tid in join_graph:
        if tid not in visited:
            if dfs(tid):
                return True
    
    return False


def _circular_wait_detected(state) -> bool:
    """
    Simplified circular wait check from current thread's perspective.
    
    If current thread times out on lock acquisition, check if:
    - Lock is held by thread T2
    - T2 is waiting on a lock held by current thread (or transitively)
    """
    if not hasattr(state, 'current_thread') or not hasattr(state, 'lock_holder'):
        return False
    
    current = state.current_thread
    holder = state.lock_holder
    
    if holder == current:
        # Can't deadlock with self (unless non-reentrant lock)
        return False
    
    # Check if holder is waiting on us (direct or indirect)
    if hasattr(state, 'lock_wait_chain'):
        # lock_wait_chain: thread -> lock -> thread -> lock -> ...
        chain = state.lock_wait_chain
        if current in chain and holder in chain:
            # Check if there's a path from holder back to current
            try:
                holder_idx = chain.index(holder)
                current_idx = chain.index(current)
                if holder_idx < current_idx:
                    # Circular: holder appears before current in wait chain
                    return True
            except ValueError:
                pass
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for DEADLOCK bug.
    
    Returns:
    - bug_type: "DEADLOCK"
    - trace: list of executed instructions
    - final_state: description of deadlock state
    - threads_involved: thread IDs in circular wait
    - lock_cycle: sequence of locks forming the cycle
    - lock_ordering_violation: (lock1, lock2) pairs with conflicting orders
    """
    threads_involved = []
    lock_cycle = []
    ordering_violations = []
    deadlock_type = "unknown"
    
    # Extract RAG cycle
    if hasattr(state, 'lock_wait_graph'):
        cycle = _extract_cycle_from_rag(state.lock_wait_graph)
        if cycle:
            lock_cycle = cycle
            # Extract thread IDs involved
            threads_involved = [node for node in cycle if isinstance(node, str) and node.startswith('T')]
            deadlock_type = "resource_allocation_graph_cycle"
    
    # Extract lock ordering violations
    if hasattr(state, 'lock_acquisition_orders'):
        violations = _extract_ordering_violations(state.lock_acquisition_orders)
        if violations:
            ordering_violations = violations
            if not deadlock_type or deadlock_type == "unknown":
                deadlock_type = "lock_ordering_violation"
    
    # Extract thread join cycle
    if hasattr(state, 'thread_join_graph'):
        join_cycle = _extract_thread_join_cycle(state.thread_join_graph)
        if join_cycle:
            threads_involved = join_cycle
            deadlock_type = "thread_join_circular_dependency"
    
    return {
        'bug_type': 'DEADLOCK',
        'trace': path_trace,
        'final_state': _describe_deadlock_state(state),
        'threads_involved': threads_involved,
        'lock_cycle': lock_cycle,
        'lock_ordering_violations': ordering_violations,
        'deadlock_type': deadlock_type,
        'path_condition': str(state.path_condition) if hasattr(state, 'path_condition') else None,
    }


def _extract_cycle_from_rag(wait_graph: dict) -> list:
    """Extract the actual cycle from RAG (for witness trace)."""
    if not wait_graph:
        return []
    
    threads = wait_graph.get('threads', {})
    locks = wait_graph.get('locks', {})
    
    adj = {}
    for tid, tinfo in threads.items():
        if tid not in adj:
            adj[tid] = []
        waiting_on = tinfo.get('waiting_on')
        if waiting_on:
            adj[tid].append(waiting_on)
    
    for lid, linfo in locks.items():
        if lid not in adj:
            adj[lid] = []
        held_by = linfo.get('held_by')
        if held_by:
            adj[lid].append(held_by)
    
    # Find cycle using DFS
    visited = set()
    rec_stack = []
    
    def dfs(node):
        visited.add(node)
        rec_stack.append(node)
        
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                cycle = dfs(neighbor)
                if cycle:
                    return cycle
            elif neighbor in rec_stack:
                # Found cycle: extract from rec_stack
                idx = rec_stack.index(neighbor)
                return rec_stack[idx:]
        
        rec_stack.pop()
        return None
    
    for node in list(threads.keys()) + list(locks.keys()):
        if node not in visited:
            cycle = dfs(node)
            if cycle:
                return cycle
    
    return []


def _extract_ordering_violations(acquisition_orders: list) -> list:
    """Extract pairs of locks with conflicting acquisition orders."""
    violations = []
    seen_orders = {}
    
    for thread_id, lock_seq in acquisition_orders:
        for i in range(len(lock_seq)):
            for j in range(i + 1, len(lock_seq)):
                lock1, lock2 = lock_seq[i], lock_seq[j]
                if lock1 == lock2:
                    continue
                
                pair = (lock1, lock2)
                if pair not in seen_orders:
                    seen_orders[pair] = []
                seen_orders[pair].append(thread_id)
    
    for (lock1, lock2), threads1 in seen_orders.items():
        reverse_pair = (lock2, lock1)
        if reverse_pair in seen_orders:
            threads2 = seen_orders[reverse_pair]
            violations.append({
                'locks': [lock1, lock2],
                'order1': (lock1, lock2),
                'threads1': threads1,
                'order2': (lock2, lock1),
                'threads2': threads2
            })
    
    return violations


def _extract_thread_join_cycle(join_graph: dict) -> list:
    """Extract thread IDs forming a join() circular dependency."""
    visited = set()
    rec_stack = []
    
    def dfs(node):
        visited.add(node)
        rec_stack.append(node)
        
        for neighbor in join_graph.get(node, []):
            if neighbor not in visited:
                cycle = dfs(neighbor)
                if cycle:
                    return cycle
            elif neighbor in rec_stack:
                idx = rec_stack.index(neighbor)
                return rec_stack[idx:]
        
        rec_stack.pop()
        return None
    
    for tid in join_graph:
        if tid not in visited:
            cycle = dfs(tid)
            if cycle:
                return cycle
    
    return []


def _describe_deadlock_state(state) -> str:
    """Generate human-readable description of deadlock state."""
    parts = []
    
    if hasattr(state, 'lock_wait_graph') and state.lock_wait_graph is not None:
        threads = state.lock_wait_graph.get('threads', {})
        locks = state.lock_wait_graph.get('locks', {})
        parts.append(f"Threads: {len(threads)}, Locks: {len(locks)}")
        
        waiting = sum(1 for t in threads.values() if t.get('waiting_on'))
        parts.append(f"Waiting threads: {waiting}")
    
    if hasattr(state, 'current_thread') and state.current_thread is not None:
        parts.append(f"Current thread: {state.current_thread}")
    
    if hasattr(state, 'exception') and state.exception is not None:
        parts.append(f"Exception: {state.exception}")
    
    return "; ".join(parts) if parts else "Deadlock detected"


def check_symbolic(symbolic_state) -> Optional[z3.BoolRef]:
    """
    Symbolic predicate for DEADLOCK.
    
    Returns Z3 constraint expressing deadlock condition:
    - Circular wait in lock wait graph (encoded symbolically)
    - All threads blocked condition
    - Lock ordering violation pattern
    
    This is challenging to encode symbolically because:
    1. Graph cycle detection is not directly expressible in Z3
    2. We need bounded unrolling or abstraction
    
    Approach:
    - Use bounded graph encoding (fixed number of threads/locks)
    - Express transitive closure of wait relation
    - Check for cycle via path constraints
    
    For simplicity, we check explicit deadlock flags set by VM.
    """
    if hasattr(symbolic_state, 'deadlock_flag'):
        return symbolic_state.deadlock_flag
    
    # More sophisticated: encode lock wait graph symbolically
    # and check for cycles (requires fixpoint / bounded unrolling)
    # For now, rely on concrete detection in VM
    
    return None
