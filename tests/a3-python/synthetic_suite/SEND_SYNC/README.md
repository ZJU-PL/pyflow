# SEND_SYNC Synthetic Test Suite

## Bug Type Definition

**SEND_SYNC** represents thread-safety contract violations in Python. This includes:
- Non-thread-safe objects passed between threads without synchronization
- Shared mutable state without proper protection
- Reentrancy violations (e.g., signal handlers calling non-reentrant functions)

## Python-Specific Interpretation

In Rust, `Send` and `Sync` are traits that ensure types can be safely transferred across thread boundaries or shared between threads. Python doesn't have such compile-time guarantees, so SEND_SYNC violations manifest as runtime errors when:

1. **Non-thread-safe objects are shared**: File objects, generators, iterators
2. **Mutable defaults shared across threads**: Functions with mutable default arguments
3. **Reentrancy violations**: Signal handlers calling functions with global state

## Test Cases

### True Positives (Expected: BUG)

1. **tp_01_file_object_shared_across_threads.py**
   - Shares a file object across multiple threads
   - File I/O operations are not atomic, leading to interleaved/corrupted writes
   - Bug: Non-thread-safe resource sharing

2. **tp_02_mutable_default_shared_across_threads.py**
   - Function with mutable default argument called from multiple threads
   - All threads share the same default list instance
   - Bug: Shared mutable state without synchronization

3. **tp_03_generator_shared_between_threads.py**
   - Single generator shared across multiple threads
   - Generator internal state (frame, locals, instruction pointer) corrupted
   - Bug: Stateful iterator shared without protection

4. **tp_04_iterator_shared_across_threads.py**
   - Single iterator consumed by multiple threads
   - Position tracking corrupted by concurrent next() calls
   - Bug: Non-thread-safe iterator sharing

5. **tp_05_non_reentrant_function_recursive_signal.py**
   - Signal handler calls function with global state
   - Function can be interrupted mid-execution, causing reentrancy
   - Bug: Reentrancy violation via signal handler

### True Negatives (Expected: SAFE)

1. **tn_01_immutable_data_sharing.py**
   - Shares immutable tuple across threads
   - Immutable data can be safely read concurrently
   - Safe: No mutable state shared

2. **tn_02_deep_copy_before_send.py**
   - Deep copies data before passing to each thread
   - Each thread operates on independent copy
   - Safe: No shared mutable state

3. **tn_03_queue_based_message_passing.py**
   - Uses thread-safe Queue for inter-thread communication
   - Queue provides internal synchronization
   - Safe: Thread-safe communication primitive

4. **tn_04_thread_local_storage.py**
   - Uses threading.local() for thread-local storage
   - Each thread has its own independent namespace
   - Safe: No sharing between threads

5. **tn_05_per_thread_file_objects.py**
   - Each thread creates and uses its own file object
   - No file objects shared across threads
   - Safe: Independent per-thread resources

## Semantic Detection Strategy

A barrier-certificate-based analyzer should detect SEND_SYNC violations by:

1. **Tracking object ownership and aliasing**:
   - Model which objects are accessible from which threads
   - Detect when mutable objects flow to multiple threads

2. **Modeling thread-safety contracts**:
   - File objects: `thread_safe = False`
   - Generators/iterators: `thread_safe = False` (stateful)
   - Queue: `thread_safe = True` (synchronized)
   - Immutable types: `thread_safe = True` (read-only)

3. **Reachability to unsafe state**:
   - Unsafe_SEND_SYNC(σ) = thread T1 and T2 can both access mutable object O where O.thread_safe = False AND no lock protects O

4. **Reentrancy analysis**:
   - Track which functions access global/shared state
   - Detect when such functions can be called from signal handlers
   - Model signal delivery as nondeterministic interruption

## Expected Analyzer Behavior

- **True Positives**: Should report BUG with trace showing:
  - Object allocation
  - Object passed to thread creation (Thread constructor)
  - Concurrent access from multiple threads
  
- **True Negatives**: Should report SAFE because:
  - Immutable data: no mutation operations possible
  - Deep copy: separate object graphs per thread
  - Queue: internal synchronization contract
  - Thread-local: per-thread namespaces proven disjoint
  - Per-thread resources: ownership analysis shows no sharing

## Notes

- Python's GIL doesn't prevent SEND_SYNC violations; operations can still interleave
- Signal handlers can interrupt at bytecode boundaries, causing reentrancy issues
- Some violations may only manifest as data corruption rather than crashes
