"""
DATA_RACE True Negative #4: Queue-based thread communication

Bug type: DATA_RACE
Expected: SAFE (no race)
Reason: Thread-safe Queue for communication (no direct shared state)
Safe pattern: queue.Queue is internally synchronized
"""

import threading
import queue

def producer(q):
    for i in range(1000):
        q.put(i)
    q.put(None)  # Sentinel

def consumer(q, results):
    total = 0
    while True:
        item = q.get()
        if item is None:
            break
        total += item
    # Safe: each consumer has its own results slot
    results.append(total)

def main():
    q = queue.Queue()
    results = []
    
    prod = threading.Thread(target=producer, args=(q,))
    cons = threading.Thread(target=consumer, args=(q, results))
    
    prod.start()
    cons.start()
    prod.join()
    cons.join()
    
    print(f"Total: {results[0]}")

if __name__ == "__main__":
    main()
