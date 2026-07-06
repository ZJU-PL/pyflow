# USE_AFTER_FREE Synthetic Test Suite

## Bug Type Definition
**USE_AFTER_FREE**: Accessing a resource, object, or handle after it has been freed, closed, or deleted.

In Python, this manifests as:
- Using file handles after `close()`
- Accessing objects after `del` when only weak references remain
- Using resources outside context manager scope
- Socket/connection I/O after close
- Iterator use after collection deletion

## True Positives (Must Detect as BUG)

1. **tp_01_file_use_after_close.py**: File write after calling close()
   - Opens file, closes it, then attempts write
   - Classic use-after-free: freed resource usage

2. **tp_02_iterator_after_del.py**: Iterator use after deleting collection
   - Creates iterator, deletes collection, attempts next()
   - Iterator holds reference to freed state

3. **tp_03_context_manager_after_exit.py**: Resource use after with-block
   - File handle used outside with-block scope
   - Context manager freed the resource at exit

4. **tp_04_weakref_after_del.py**: Weakref dereference after del
   - Dereferences weakref after referent is deleted
   - No None check before use

5. **tp_05_socket_after_close.py**: Socket I/O after close()
   - Socket send after close() call
   - Network resource use-after-free

## True Negatives (Must NOT Flag as BUG)

1. **tn_01_proper_lifecycle.py**: Correct resource lifecycle
   - Uses file before close, respects lifecycle
   - No use-after-free

2. **tn_02_context_manager_proper.py**: Proper with-block usage
   - All usage within context manager scope
   - Automatic cleanup without dangling use

3. **tn_03_copy_before_del.py**: Copy before del pattern
   - Makes independent copy before deletion
   - Safe to use copy after original deleted

4. **tn_04_weakref_checked.py**: Defensive weakref check
   - Checks weakref() is not None before use
   - Proper defensive programming

5. **tn_05_multiple_references.py**: Multiple references
   - Multiple references prevent freeing
   - del removes one reference; object still alive

## Semantic Modeling Notes

For barrier-certificate verification, USE_AFTER_FREE requires tracking:
- Resource states (open/closed/freed)
- Reference counts or liveness analysis
- Scope/lifetime boundaries (context manager entry/exit)
- Weak vs strong references

The unsafe region `U_USE_AFTER_FREE(σ)` is reached when:
```
σ.operation_target in σ.freed_resources
```

For Python:
- File operations after close() → ValueError ("I/O operation on closed file")
- Socket operations after close() → OSError
- Weakref dereference may return None or raise ReferenceError
- Iterator after collection deleted may work (GC hasn't run) or crash

The semantic model must track resource lifecycle explicitly to catch these bugs.
