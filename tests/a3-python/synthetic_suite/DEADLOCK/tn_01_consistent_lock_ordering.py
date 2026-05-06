"""
DEADLOCK True Negative #1: Consistent lock ordering prevents deadlock

Expected: SAFE (no DEADLOCK)
Reason: Both threads always acquire locks in the same order (A before B).
        Consistent lock ordering eliminates circular wait, preventing deadlock.

Bug Type: DEADLOCK
Severity: N/A (safe pattern)
"""

import threading
import time

lock_a = threading.Lock()
lock_b = threading.Lock()


def thread1_func():
    """Thread 1: Always acquires A before B"""
    with lock_a:
        print("Thread 1: Acquired lock_a")
        time.sleep(0.1)
        with lock_b:
            print("Thread 1: Acquired lock_b")
            print("Thread 1: Critical section complete")


def thread2_func():
    """Thread 2: Also acquires A before B (same order)"""
    with lock_a:
        print("Thread 2: Acquired lock_a")
        time.sleep(0.1)
        with lock_b:
            print("Thread 2: Acquired lock_b")
            print("Thread 2: Critical section complete")


if __name__ == "__main__":
    t1 = threading.Thread(target=thread1_func)
    t2 = threading.Thread(target=thread2_func)

    t1.start()
    t2.start()

    # Both threads complete successfully - no deadlock
    t1.join()
    t2.join()

    print("Completed successfully - consistent lock ordering prevents deadlock")
