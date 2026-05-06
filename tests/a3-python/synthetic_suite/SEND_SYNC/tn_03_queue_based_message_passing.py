"""
SEND_SYNC True Negative #3: Queue-based message passing
Expected: SAFE

Rationale: Queue objects are thread-safe and designed for inter-thread
communication. Using Queue for passing data between threads avoids
direct sharing of mutable state.

Safe pattern: Queue-based message passing
"""

import threading
import queue


def producer(q, count):
    """Producer that sends messages via queue"""
    for i in range(count):
        item = {"id": i, "data": f"item-{i}"}
        q.put(item)
    
    # Send sentinel to signal completion
    q.put(None)


def consumer(q, worker_id, results):
    """Consumer that receives messages via queue"""
    processed = 0
    while True:
        item = q.get()
        if item is None:
            # Sentinel received, put it back for other consumers
            q.put(None)
            break
        
        # Process the item
        processed += 1
        
        q.task_done()
    
    results[worker_id] = processed


def main():
    # Thread-safe queue for communication
    work_queue = queue.Queue()
    
    results = {}
    
    # Start producer
    producer_thread = threading.Thread(target=producer, args=(work_queue, 1000))
    producer_thread.start()
    
    # Start consumers
    consumers = []
    for i in range(3):
        t = threading.Thread(target=consumer, args=(work_queue, i, results))
        consumers.append(t)
        t.start()
    
    producer_thread.join()
    
    for t in consumers:
        t.join()
    
    # All items processed safely via queue


if __name__ == "__main__":
    main()
