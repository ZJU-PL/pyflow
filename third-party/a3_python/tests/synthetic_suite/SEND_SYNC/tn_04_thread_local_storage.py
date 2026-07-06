"""
SEND_SYNC True Negative #4: Thread-local storage
Expected: SAFE

Rationale: threading.local() provides thread-local storage where each
thread has its own independent namespace. No sharing means no thread-
safety concerns.

Safe pattern: Thread-local storage
"""

import threading


# Thread-local storage
thread_local = threading.local()


def initialize_thread():
    """Initialize thread-local data"""
    thread_local.counter = 0
    thread_local.items = []


def worker(worker_id, iterations):
    """Worker that uses only thread-local storage"""
    initialize_thread()
    
    # All operations on thread-local data
    for i in range(iterations):
        thread_local.counter += 1
        thread_local.items.append(f"{worker_id}-{i}")
    
    print(f"Worker {worker_id}: counter={thread_local.counter}, "
          f"items={len(thread_local.items)}")


def main():
    threads = []
    
    # Each thread operates on its own thread-local storage
    for i in range(5):
        t = threading.Thread(target=worker, args=(i, 1000))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # No shared mutable state, each thread has its own namespace


if __name__ == "__main__":
    main()
