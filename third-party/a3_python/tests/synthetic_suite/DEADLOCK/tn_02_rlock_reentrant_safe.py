"""
DEADLOCK True Negative #2: RLock for reentrant access

Expected: SAFE (no DEADLOCK)
Reason: threading.RLock (reentrant lock) allows the same thread to acquire it multiple times.
        No self-deadlock occurs even with recursive calls.

Bug Type: DEADLOCK
Severity: N/A (safe pattern)
"""

import threading


def recursive_function(rlock, depth):
    """Recursively acquires the same RLock - safe with reentrant lock"""
    if depth == 0:
        return

    print(f"Depth {depth}: Trying to acquire RLock...")
    with rlock:
        print(f"Depth {depth}: Acquired RLock")
        # Recursive call safely re-acquires the same RLock
        recursive_function(rlock, depth - 1)
        print(f"Depth {depth}: Released RLock")


if __name__ == "__main__":
    rlock = threading.RLock()  # Reentrant lock - allows same thread re-entry

    # Safe: RLock allows recursive acquisition
    recursive_function(rlock, 3)

    print("Completed successfully - RLock allows reentrant acquisition")
