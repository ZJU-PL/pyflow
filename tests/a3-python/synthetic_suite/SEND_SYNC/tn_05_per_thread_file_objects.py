"""
SEND_SYNC True Negative #5: Per-thread file objects
Expected: SAFE

Rationale: When each thread creates and uses its own file object, there
is no shared state. Each thread operates on an independent resource.

Safe pattern: Per-thread resources (no sharing)
"""

import threading


def worker(worker_id, iterations):
    """Worker that creates its own file object"""
    # Each worker creates its own file
    filename = f"output_worker_{worker_id}.txt"
    
    with open(filename, "w") as f:
        # Only this thread uses this file object
        for i in range(iterations):
            f.write(f"Worker {worker_id}: item {i}\n")
    
    print(f"Worker {worker_id} completed")


def main():
    threads = []
    
    # Each thread gets its own independent file
    for i in range(5):
        t = threading.Thread(target=worker, args=(i, 100))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # No file objects shared across threads


if __name__ == "__main__":
    main()
