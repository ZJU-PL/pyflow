"""
DEADLOCK True Positive #5: Nested lock acquisition with mixed ordering

Expected: BUG (DEADLOCK)
Reason: Function f1 acquires locks in order A→B→C.
        Function f2 acquires locks in order C→B→A (reverse order).
        When called concurrently, this creates deadlock potential.

Bug Type: DEADLOCK
Severity: Critical - inconsistent lock ordering across code paths
"""

import threading
import time

lock_a = threading.Lock()
lock_b = threading.Lock()
lock_c = threading.Lock()


def function1():
    """Acquires locks in order: A → B → C"""
    with lock_a:
        print("Function1: Acquired lock_a")
        time.sleep(0.05)
        with lock_b:
            print("Function1: Acquired lock_b")
            time.sleep(0.05)
            with lock_c:
                print("Function1: Acquired lock_c")


def function2():
    """Acquires locks in reverse order: C → B → A"""
    with lock_c:
        print("Function2: Acquired lock_c")
        time.sleep(0.05)
        with lock_b:
            print("Function2: Acquired lock_b")
            time.sleep(0.05)
            with lock_a:
                print("Function2: Acquired lock_a")


if __name__ == "__main__":
    t1 = threading.Thread(target=function1)
    t2 = threading.Thread(target=function2)

    t1.start()
    t2.start()

    # Deadlock: conflicting lock orderings
    t1.join()
    t2.join()

    print("Completed (this will never print)")
