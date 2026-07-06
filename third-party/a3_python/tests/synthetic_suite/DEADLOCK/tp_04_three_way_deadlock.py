"""
DEADLOCK True Positive #4: Three-way circular deadlock

Expected: BUG (DEADLOCK)
Reason: Thread 1 acquires A then tries B.
        Thread 2 acquires B then tries C.
        Thread 3 acquires C then tries A.
        This creates a circular wait cycle A→B→C→A leading to deadlock.

Bug Type: DEADLOCK
Severity: Critical - multi-thread circular dependency
"""

import threading
import time

lock_a = threading.Lock()
lock_b = threading.Lock()
lock_c = threading.Lock()


def thread1_func():
    """Thread 1: A → B"""
    with lock_a:
        print("Thread 1: Acquired lock_a")
        time.sleep(0.1)
        print("Thread 1: Trying to acquire lock_b...")
        with lock_b:
            print("Thread 1: Acquired lock_b")


def thread2_func():
    """Thread 2: B → C"""
    with lock_b:
        print("Thread 2: Acquired lock_b")
        time.sleep(0.1)
        print("Thread 2: Trying to acquire lock_c...")
        with lock_c:
            print("Thread 2: Acquired lock_c")


def thread3_func():
    """Thread 3: C → A (completes the cycle)"""
    with lock_c:
        print("Thread 3: Acquired lock_c")
        time.sleep(0.1)
        print("Thread 3: Trying to acquire lock_a...")
        with lock_a:
            print("Thread 3: Acquired lock_a")


if __name__ == "__main__":
    t1 = threading.Thread(target=thread1_func)
    t2 = threading.Thread(target=thread2_func)
    t3 = threading.Thread(target=thread3_func)

    t1.start()
    t2.start()
    t3.start()

    # All three threads will deadlock
    t1.join()
    t2.join()
    t3.join()

    print("Completed (this will never print)")
