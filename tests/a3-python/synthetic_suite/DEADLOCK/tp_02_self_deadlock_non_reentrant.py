"""
DEADLOCK True Positive #2: Self-deadlock on non-reentrant lock

Expected: BUG (DEADLOCK)
Reason: A single thread tries to acquire the same non-reentrant Lock twice.
        threading.Lock is not reentrant, so this causes immediate deadlock.

Bug Type: DEADLOCK
Severity: Critical - thread hangs on self
"""

import threading


def recursive_function(lock, depth):
    """Recursively acquires the same lock - deadlocks on second acquisition"""
    if depth == 0:
        return

    print(f"Depth {depth}: Trying to acquire lock...")
    with lock:
        print(f"Depth {depth}: Acquired lock")
        # Recursive call tries to acquire the same lock again - DEADLOCK!
        recursive_function(lock, depth - 1)


if __name__ == "__main__":
    lock = threading.Lock()  # Non-reentrant lock

    # This will deadlock on the second call when it tries to re-acquire
    recursive_function(lock, 2)

    print("Completed (this will never print)")
