#!/usr/bin/env python3
"""
Concurrency and Threading Example for PyFlow

This example demonstrates Python threading, synchronization primitives,
and concurrent programming patterns for static analysis testing.

Usage:
    pyflow optimize concurrency_threading.py --analysis ipa
    pyflow callgraph concurrency_threading.py
"""

import threading
import time
import queue
from typing import List, Any
from concurrent.futures import ThreadPoolExecutor

# Thread-safe counter
class ThreadSafeCounter:
    """Thread-safe counter using locks."""
    
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = threading.Lock()
    
    def increment(self) -> int:
        with self._lock:
            self._value += 1
            return self._value
    
    def get_value(self) -> int:
        with self._lock:
            return self._value

# Producer-Consumer pattern
class ProducerConsumer:
    """Producer-Consumer pattern implementation."""
    
    def __init__(self, queue_size: int = 10):
        self.queue = queue.Queue(maxsize=queue_size)
        self.producers_done = threading.Event()
    
    def producer(self, producer_id: int, num_items: int):
        """Producer function."""
        for i in range(num_items):
            item = f"Producer-{producer_id}-Item-{i}"
            self.queue.put(item)
            time.sleep(0.1)
        print(f"Producer {producer_id} finished")
    
    def consumer(self, consumer_id: int):
        """Consumer function."""
        while True:
            try:
                item = self.queue.get(timeout=1.0)
                print(f"Consumer-{consumer_id} consumed: {item}")
                self.queue.task_done()
                time.sleep(0.1)
            except queue.Empty:
                if self.producers_done.is_set():
                    break
        print(f"Consumer {consumer_id} finished")
    
    def run(self, num_producers: int, num_consumers: int, items_per_producer: int):
        """Run the producer-consumer simulation."""
        # Start producers
        producer_threads = []
        for i in range(num_producers):
            thread = threading.Thread(target=self.producer, args=(i, items_per_producer))
            producer_threads.append(thread)
            thread.start()
        
        # Start consumers
        consumer_threads = []
        for i in range(num_consumers):
            thread = threading.Thread(target=self.consumer, args=(i,))
            consumer_threads.append(thread)
            thread.start()
        
        # Wait for producers
        for thread in producer_threads:
            thread.join()
        
        self.producers_done.set()
        
        # Wait for consumers
        for thread in consumer_threads:
            thread.join()

# Thread pools
def cpu_bound_task(n: int) -> int:
    """CPU-bound task."""
    result = 0
    for i in range(n):
        result += i ** 2
    return result

def io_bound_task(duration: float) -> str:
    """IO-bound task."""
    time.sleep(duration)
    return f"Completed after {duration}s"

def test_thread_pool():
    """Test thread pool usage."""
    with ThreadPoolExecutor(max_workers=4) as executor:
        # Submit IO-bound tasks
        io_futures = [executor.submit(io_bound_task, 0.1) for _ in range(5)]
        
        # Submit CPU-bound tasks
        cpu_futures = [executor.submit(cpu_bound_task, 1000) for _ in range(3)]
        
        # Collect results
        io_results = [future.result() for future in io_futures]
        cpu_results = [future.result() for future in cpu_futures]
        
        print(f"IO results: {io_results}")
        print(f"CPU results: {cpu_results}")

# Semaphores
class BoundedBuffer:
    """Bounded buffer using semaphores."""
    
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.buffer = []
        self.mutex = threading.Lock()
        self.empty_slots = threading.Semaphore(capacity)
        self.filled_slots = threading.Semaphore(0)
    
    def put(self, item: Any) -> None:
        self.empty_slots.acquire()
        with self.mutex:
            self.buffer.append(item)
        self.filled_slots.release()
    
    def get(self) -> Any:
        self.filled_slots.acquire()
        with self.mutex:
            item = self.buffer.pop(0)
        self.empty_slots.release()
        return item

# Thread communication with events
class ThreadCommunication:
    """Thread communication using events."""
    
    def __init__(self):
        self.data_ready = threading.Event()
        self.data_processed = threading.Event()
        self.data = None
        self.result = None
    
    def producer(self):
        """Producer thread."""
        time.sleep(0.5)  # Simulate work
        self.data = "Important data"
        self.data_ready.set()  # Signal data is ready
        self.data_processed.wait()  # Wait for processing
    
    def consumer(self):
        """Consumer thread."""
        self.data_ready.wait()  # Wait for data
        self.result = f"Processed: {self.data}"
        self.data_processed.set()  # Signal processing done
    
    def run(self):
        """Run producer-consumer communication."""
        producer_thread = threading.Thread(target=self.producer)
        consumer_thread = threading.Thread(target=self.consumer)
        
        producer_thread.start()
        consumer_thread.start()
        
        producer_thread.join()
        consumer_thread.join()
        
        return self.result

if __name__ == "__main__":
    print("=== Thread-Safe Counter ===")
    counter = ThreadSafeCounter(0)
    
    def increment_worker(counter: ThreadSafeCounter, iterations: int):
        for _ in range(iterations):
            counter.increment()
            time.sleep(0.001)
    
    threads = []
    for i in range(3):
        thread = threading.Thread(target=increment_worker, args=(counter, 100))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print(f"Final counter value: {counter.get_value()}")
    
    print("\n=== Producer-Consumer Pattern ===")
    pc = ProducerConsumer(5)
    pc.run(2, 2, 3)
    
    print("\n=== Thread Pool ===")
    test_thread_pool()
    
    print("\n=== Bounded Buffer ===")
    buffer = BoundedBuffer(3)
    
    def producer(buffer: BoundedBuffer):
        for i in range(5):
            buffer.put(f"item-{i}")
            time.sleep(0.1)
    
    def consumer(buffer: BoundedBuffer):
        for i in range(5):
            item = buffer.get()
            print(f"Consumed: {item}")
            time.sleep(0.1)
    
    producer_thread = threading.Thread(target=producer, args=(buffer,))
    consumer_thread = threading.Thread(target=consumer, args=(buffer,))
    
    producer_thread.start()
    consumer_thread.start()
    
    producer_thread.join()
    consumer_thread.join()
    
    print("\n=== Thread Communication ===")
    tc = ThreadCommunication()
    result = tc.run()
    print(f"Communication result: {result}")
