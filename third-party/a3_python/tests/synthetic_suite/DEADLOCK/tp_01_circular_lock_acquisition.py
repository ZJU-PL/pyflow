"""
DEADLOCK True Positive #1: Circular lock acquisition (classic AB-BA deadlock)

Expected: BUG (DEADLOCK)
Reason: Thread 1 acquires lock_a then tries lock_b; Thread 2 acquires lock_b then tries lock_a.
        Classic circular wait condition leading to deadlock.

Bug Type: DEADLOCK
Severity: Critical - program hangs indefinitely
"""

import threading
import time

lock_a = threading.Lock()
lock_b = threading.Lock()


def thread1_func():
    """Thread 1: Acquires A, then tries to acquire B"""
    with lock_a:
        print("Thread 1: Acquired lock_a")
        time.sleep(0.1)  # Give thread 2 time to acquire lock_b
        print("Thread 1: Trying to acquire lock_b...")
        with lock_b:
            print("Thread 1: Acquired lock_b")


def thread2_func():
    """Thread 2: Acquires B, then tries to acquire A"""
    with lock_b:
        print("Thread 2: Acquired lock_b")
        time.sleep(0.1)  # Give thread 1 time to acquire lock_a
        print("Thread 2: Trying to acquire lock_a...")
        with lock_a:
            print("Thread 2: Acquired lock_a")


if __name__ == "__main__":
    t1 = threading.Thread(target=thread1_func)
    t2 = threading.Thread(target=thread2_func)

    t1.start()
    t2.start()

    # This will hang forever - deadlock!
    t1.join()
    t2.join()

    print("Completed (this will never print)")
