# DOUBLE_FREE Synthetic Test Suite

## Bug Type: DOUBLE_FREE

**Definition**: Attempting to free/close/release a resource that has already been freed/closed/released.

**Python Manifestation**: In Python, this occurs when:
- Calling `close()` twice on file objects, sockets, or other resources
- Calling `__exit__()` multiple times on context managers
- Releasing resource handles multiple times

**Semantic Model**: The analyzer must track resource state transitions:
- `ResourceState = {OPEN, CLOSED}`
- `close()` transitions `OPEN → CLOSED`
- A second `close()` on `CLOSED` state is `DOUBLE_FREE`

---

## True Positives (Expected: BUG - DOUBLE_FREE)

### tp_01_file_double_close.py
Direct double-close: `f.close(); f.close()`

**Detection strategy**:
- Track file object state through `open()` and `close()` calls
- First `close()` marks file as closed
- Second `close()` operates on closed file → DOUBLE_FREE

### tp_02_socket_double_close.py
Socket double-close: `sock.close(); sock.close()`

**Detection strategy**:
- Model socket lifecycle (open → closed)
- Track socket state transitions
- Second close on closed socket → DOUBLE_FREE

### tp_03_nested_context_double_exit.py
Manual `__exit__` after with-block: `with r: ...; r.__exit__(...)`

**Detection strategy**:
- Model with-statement semantics (automatic __exit__ at block end)
- Track context manager exit status
- Manual __exit__ after automatic exit → DOUBLE_FREE

### tp_04_conditional_double_close.py
Conditional path double-close: both branches lead to two total closes

**Detection strategy**:
- Path-sensitive analysis through conditional branches
- Track close() calls on all paths
- At least one path has two close() calls → DOUBLE_FREE

### tp_05_exception_handler_double_close.py
Finally block close + post-try close: `try: ... finally: f.close(); f.close()`

**Detection strategy**:
- Model finally-block semantics (always executes)
- Track close() in finally and after try-except
- Both close() calls execute → DOUBLE_FREE

---

## True Negatives (Expected: SAFE)

### tn_01_single_close_guard.py
Guard prevents double-close: `if not f.closed: f.close()`

**Verification strategy**:
- Analyze guard condition `f.closed`
- Prove guard prevents second close when already closed
- No path leads to double-close → SAFE

### tn_02_idempotent_cleanup.py
Idempotent close pattern with internal state tracking

**Verification strategy**:
- Analyze internal `_closed` flag
- Prove close() is no-op when already closed
- Multiple close() calls are safe → SAFE

### tn_03_context_manager_proper.py
Proper with-statement usage (no manual close afterward)

**Verification strategy**:
- Model with-statement guarantees single __exit__
- No manual close/exit after with-block
- Resource closed exactly once → SAFE

### tn_04_flag_based_prevention.py
Explicit flag prevents double-close in all paths

**Verification strategy**:
- Analyze `is_closed` flag across all paths
- Prove flag ensures at-most-once semantics
- No path leads to double-close → SAFE

### tn_05_separate_resources.py
Two separate resources, each closed once

**Verification strategy**:
- Track resource identity (different objects)
- Each close() operates on distinct resource
- No single resource closed twice → SAFE

---

## Coverage Summary

- **True Positives**: 5 cases (direct/socket/context/conditional/exception)
- **True Negatives**: 5 cases (guard/idempotent/context-proper/flag/separate)
- **Total**: 10 test cases

## Expected Analyzer Behavior

For each true positive:
1. Produce `BUG: DOUBLE_FREE` verdict
2. Extract witness trace showing two close/exit operations on same resource
3. Identify the resource (file path/socket/object) and both close sites

For each true negative:
1. Produce `SAFE` verdict with proof/invariant
2. Or produce `UNKNOWN` if proof not found (acceptable, but no false BUG)
3. Never produce `BUG` (false positive)

## Evaluation Metrics

- **Precision**: (True BUGs found) / (Total BUGs reported) = 1.0 target
- **Recall**: (True BUGs found) / (Total actual BUGs) = 1.0 target
- **False Positive Rate**: Should be 0 on true negatives
- **False Negative Rate**: Should be 0 on true positives
