"""
DEADLOCK True Negative #5: Lock-free coordination with queue

Expected: SAFE (no DEADLOCK)
Reason: Uses threading.Queue for inter-thread communication.
        Queue is internally synchronized and deadlock-free for producer-consumer patterns.

Bug Type: DEADLOCK
Severity: N/A (safe pattern)
"""

import threading
import queue
import time


def producer_thread(q):
    """Producer: Puts items into queue"""
    for i in range(5):
        item = f"item_{i}"
        print(f"Producer: Producing {item}")
        q.put(item)
        time.sleep(0.1)
    q.put(None)  # Sentinel to signal completion


def consumer_thread(q):
    """Consumer: Gets items from queue"""
    while True:
        item = q.get()
        if item is None:
            print("Consumer: Received sentinel, exiting")
            q.task_done()
            break
        print(f"Consumer: Consumed {item}")
        q.task_done()
        time.sleep(0.05)


if __name__ == "__main__":
    work_queue = queue.Queue()

    producer = threading.Thread(target=producer_thread, args=(work_queue,))
    consumer = threading.Thread(target=consumer_thread, args=(work_queue,))

    producer.start()
    consumer.start()

    producer.join()
    consumer.join()

    print("Completed successfully - queue-based coordination is deadlock-free")
