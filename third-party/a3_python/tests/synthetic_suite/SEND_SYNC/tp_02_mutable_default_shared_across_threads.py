"""
SEND_SYNC True Positive #2: Mutable default argument shared across threads
Expected: BUG (SEND_SYNC violation)

Rationale: Mutable default arguments are shared across all calls. When
multiple threads call the same function with the default argument, they
share the same mutable object without synchronization.

Bug type: Mutable default shared across threads
"""

import threading


def accumulate(value, storage=[]):
    """Function with mutable default argument"""
    storage.append(value)
    return len(storage)


def worker(thread_id):
    """Worker that uses mutable default"""
    for i in range(1000):
        result = accumulate(f"{thread_id}-{i}")


def main():
    # Multiple threads call accumulate() which shares the default list
    threads = []
    for i in range(5):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # The shared default list has been mutated concurrently


if __name__ == "__main__":
    main()
