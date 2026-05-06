"""
SEND_SYNC True Positive #4: Iterator shared across threads
Expected: BUG (SEND_SYNC violation)

Rationale: Iterators maintain internal position state. When multiple
threads call next() on the same iterator without synchronization, the
position tracking can become corrupted, leading to skipped elements,
duplicate processing, or crashes.

Bug type: Non-thread-safe iterator shared between threads
"""

import threading


def worker(iterator, results, worker_id):
    """Worker that consumes from shared iterator"""
    items = []
    try:
        for _ in range(500):
            val = next(iterator)
            items.append(val)
    except StopIteration:
        pass
    results[worker_id] = items


def main():
    # Create an iterator and share it across threads
    data = range(10000)
    iterator = iter(data)
    
    results = {}
    threads = []
    
    # Multiple threads consuming from the same iterator
    for i in range(4):
        t = threading.Thread(target=worker, args=(iterator, results, i))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Iterator state corrupted by concurrent access


if __name__ == "__main__":
    main()
