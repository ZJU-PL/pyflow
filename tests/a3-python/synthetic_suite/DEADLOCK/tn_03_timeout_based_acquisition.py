"""
DEADLOCK True Negative #3: Timeout-based lock acquisition avoids indefinite wait

Expected: SAFE (no DEADLOCK)
Reason: Using lock.acquire(timeout=...) with fallback handling prevents indefinite blocking.
        If lock can't be acquired, the thread can back off or retry, avoiding deadlock.

Bug Type: DEADLOCK
Severity: N/A (safe pattern)
"""

import threading
import time

lock_a = threading.Lock()
lock_b = threading.Lock()


def thread1_func():
    """Thread 1: Uses timeout to avoid indefinite blocking"""
    if lock_a.acquire(timeout=1.0):
        try:
            print("Thread 1: Acquired lock_a")
            time.sleep(0.1)

            # Try to acquire lock_b with timeout
            if lock_b.acquire(timeout=1.0):
                try:
                    print("Thread 1: Acquired lock_b")
                finally:
                    lock_b.release()
            else:
                print("Thread 1: Could not acquire lock_b, backing off")
        finally:
            lock_a.release()
    else:
        print("Thread 1: Could not acquire lock_a, backing off")


def thread2_func():
    """Thread 2: Also uses timeout (even with opposite order)"""
    if lock_b.acquire(timeout=1.0):
        try:
            print("Thread 2: Acquired lock_b")
            time.sleep(0.1)

            # Try to acquire lock_a with timeout
            if lock_a.acquire(timeout=1.0):
                try:
                    print("Thread 2: Acquired lock_a")
                finally:
                    lock_a.release()
            else:
                print("Thread 2: Could not acquire lock_a, backing off")
        finally:
            lock_b.release()
    else:
        print("Thread 2: Could not acquire lock_b, backing off")


if __name__ == "__main__":
    t1 = threading.Thread(target=thread1_func)
    t2 = threading.Thread(target=thread2_func)

    t1.start()
    t2.start()

    # Both threads complete (possibly with backoff) - no indefinite deadlock
    t1.join()
    t2.join()

    print("Completed successfully - timeout prevents indefinite deadlock")
