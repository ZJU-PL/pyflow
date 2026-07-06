"""
SEND_SYNC True Positive #3: Generator shared between threads
Expected: BUG (SEND_SYNC violation)

Rationale: Generators maintain internal state (frame, locals, instruction
pointer). When multiple threads call next() on the same generator without
synchronization, the internal state can be corrupted.

Bug type: Generator shared between threads
"""

import threading


def number_generator():
    """Simple generator with internal state"""
    i = 0
    while i < 10000:
        yield i
        i += 1


def worker(gen, results, worker_id):
    """Worker that consumes from shared generator"""
    count = 0
    try:
        for _ in range(5000):
            val = next(gen)
            count += 1
    except StopIteration:
        pass
    results[worker_id] = count


def main():
    # Create a single generator and share it across threads
    gen = number_generator()
    
    results = {}
    threads = []
    
    for i in range(3):
        t = threading.Thread(target=worker, args=(gen, results, i))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Generator state may be corrupted due to concurrent access


if __name__ == "__main__":
    main()
