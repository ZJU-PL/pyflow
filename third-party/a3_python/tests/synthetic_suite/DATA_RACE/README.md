# DATA_RACE Synthetic Test Suite

Bug type: **DATA_RACE** - Concurrent access to shared mutable state without proper synchronization

## True Positives (Must detect as BUG)

1. **tp_01_shared_counter_no_lock.py**: Shared counter without lock
   - Multiple threads increment shared counter without synchronization
   - Race: read-modify-write on counter (non-atomic increment)

2. **tp_02_list_append_race.py**: List append race
   - Multiple threads append to shared list without synchronization
   - Race: list.append() calls not synchronized (structure corruption possible)

3. **tp_03_dict_update_race.py**: Dictionary update race
   - Multiple threads update shared dict without synchronization
   - Race: dict updates can corrupt internal structure

4. **tp_04_check_then_act_race.py**: Check-then-act race (TOCTOU)
   - Check-then-act pattern without atomicity
   - Race: condition check and action are not atomic (balance can go negative)

5. **tp_05_attribute_race.py**: Object attribute race
   - Multiple threads modify object attributes without synchronization
   - Race: concurrent attribute reads and writes (inconsistent state)

## True Negatives (Must NOT flag as BUG)

1. **tn_01_lock_protected_counter.py**: Lock-protected counter
   - Shared counter protected by Lock
   - Safe: all accesses guarded by lock

2. **tn_02_thread_local_storage.py**: Thread-local storage
   - Each thread has its own storage (no sharing)
   - Safe: threading.local() provides per-thread state

3. **tn_03_immutable_shared_data.py**: Immutable shared data
   - Shared data is immutable (reads only)
   - Safe: immutable objects can be safely shared

4. **tn_04_queue_based_communication.py**: Queue-based thread communication
   - Thread-safe Queue for communication
   - Safe: queue.Queue is internally synchronized

5. **tn_05_atomic_operations.py**: Atomic operations with RLock
   - RLock guards check-then-act pattern atomically
   - Safe: entire critical section protected by lock

## Semantic Requirements for Detection

A DATA_RACE occurs when:
1. Multiple threads access shared mutable state
2. At least one access is a write
3. The accesses are not synchronized (no lock/atomic primitive guards them)
4. The accesses can happen concurrently (happen-before relation does not order them)

## Implementation Notes

- Python GIL provides some atomicity guarantees, but NOT for all operations
- List.append, dict updates, attribute writes can still race despite GIL
- Non-atomic operations: +=, read-modify-write, check-then-act patterns
- Detection requires: thread escape analysis + synchronization analysis + may-happen-in-parallel analysis
