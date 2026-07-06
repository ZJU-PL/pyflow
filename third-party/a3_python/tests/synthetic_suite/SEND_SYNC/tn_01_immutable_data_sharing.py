"""
SEND_SYNC True Negative #1: Immutable data sharing
Expected: SAFE

Rationale: Immutable data (strings, tuples, frozensets, numbers) can be
safely shared across threads without synchronization because they cannot
be modified after creation.

Safe pattern: Immutable data sharing
"""

import threading


def worker(data, results, worker_id):
    """Worker that reads immutable shared data"""
    # Read from the immutable tuple
    total = sum(data)
    count = len(data)
    avg = total / count if count > 0 else 0
    
    results[worker_id] = avg


def main():
    # Create immutable data structure
    shared_data = tuple(range(10000))  # Tuple is immutable
    
    results = {}
    threads = []
    
    # Multiple threads can safely read immutable data
    for i in range(5):
        t = threading.Thread(target=worker, args=(shared_data, results, i))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # All workers got the same result from immutable data


if __name__ == "__main__":
    main()
