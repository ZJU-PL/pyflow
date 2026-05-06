"""
SEND_SYNC True Negative #2: Deep copy before sending to thread
Expected: SAFE

Rationale: Making a deep copy of data before passing it to a thread
ensures each thread has its own independent copy. No shared mutable state
means no thread-safety issues.

Safe pattern: Deep copy before send
"""

import threading
import copy


class DataContainer:
    def __init__(self, items):
        self.items = items
        self.processed = []
    
    def process(self):
        for item in self.items:
            self.processed.append(item * 2)


def worker(data_container, worker_id):
    """Worker that operates on its own copy of data"""
    data_container.process()
    print(f"Worker {worker_id} processed {len(data_container.processed)} items")


def main():
    # Create original data
    original = DataContainer(list(range(1000)))
    
    threads = []
    
    # Each thread gets its own deep copy
    for i in range(5):
        # Deep copy ensures complete independence
        worker_copy = copy.deepcopy(original)
        t = threading.Thread(target=worker, args=(worker_copy, i))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Each thread modified only its own copy


if __name__ == "__main__":
    main()
