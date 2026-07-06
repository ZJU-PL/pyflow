"""
DEADLOCK True Negative #4: Single lock protects all resources

Expected: SAFE (no DEADLOCK)
Reason: Only one lock is used for all shared resources.
        No circular wait is possible with a single lock.

Bug Type: DEADLOCK
Severity: N/A (safe pattern)
"""

import threading
import time

# Single lock for all shared resources
global_lock = threading.Lock()

shared_counter_a = 0
shared_counter_b = 0


def thread1_func():
    """Thread 1: Uses single global lock"""
    global shared_counter_a, shared_counter_b

    with global_lock:
        print("Thread 1: Acquired global_lock")
        shared_counter_a += 1
        time.sleep(0.1)
        shared_counter_b += 1
        print(f"Thread 1: Updated counters (a={shared_counter_a}, b={shared_counter_b})")


def thread2_func():
    """Thread 2: Also uses same global lock"""
    global shared_counter_a, shared_counter_b

    with global_lock:
        print("Thread 2: Acquired global_lock")
        shared_counter_a += 10
        time.sleep(0.1)
        shared_counter_b += 10
        print(f"Thread 2: Updated counters (a={shared_counter_a}, b={shared_counter_b})")


if __name__ == "__main__":
    t1 = threading.Thread(target=thread1_func)
    t2 = threading.Thread(target=thread2_func)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print(
        f"Completed successfully - single lock prevents deadlock (final: a={shared_counter_a}, b={shared_counter_b})"
    )
