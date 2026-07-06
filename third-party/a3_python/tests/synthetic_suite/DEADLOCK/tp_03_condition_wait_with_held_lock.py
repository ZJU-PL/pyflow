"""
DEADLOCK True Positive #3: Condition.wait() while holding another lock

Expected: BUG (DEADLOCK)
Reason: Thread 1 holds lock_a and waits on condition (which internally needs lock_b).
        Thread 2 holds lock_b and tries to acquire lock_a before notifying.
        This creates a circular dependency leading to deadlock.

Bug Type: DEADLOCK
Severity: Critical - inter-thread coordination failure
"""

import threading
import time

lock_a = threading.Lock()
lock_b = threading.Lock()
condition = threading.Condition(lock_b)


def waiter_thread():
    """Holds lock_a while waiting on condition (which needs lock_b)"""
    with lock_a:
        print("Waiter: Acquired lock_a")
        time.sleep(0.1)  # Give notifier time to acquire lock_b
        print("Waiter: Trying to wait on condition (needs lock_b)...")
        with condition:
            condition.wait()  # Deadlock: can't acquire lock_b while lock_a is held


def notifier_thread():
    """Holds lock_b (via condition), tries to acquire lock_a before notifying"""
    with condition:
        print("Notifier: Acquired condition lock (lock_b)")
        time.sleep(0.1)  # Give waiter time to acquire lock_a
        print("Notifier: Trying to acquire lock_a before notifying...")
        with lock_a:  # Deadlock: can't acquire lock_a
            condition.notify()


if __name__ == "__main__":
    t1 = threading.Thread(target=waiter_thread)
    t2 = threading.Thread(target=notifier_thread)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print("Completed (this will never print)")
