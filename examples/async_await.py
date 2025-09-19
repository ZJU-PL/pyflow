#!/usr/bin/env python3
"""
Async/Await and Concurrency Example for PyFlow

This example demonstrates Python async/await, coroutines, and concurrency
that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize async_await.py --analysis ipa
    pyflow callgraph async_await.py
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass

# Basic async functions
async def simple_async_function(name: str) -> str:
    """Simple async function that simulates work."""
    print(f"Starting {name}")
    await asyncio.sleep(1)  # Simulate async work
    print(f"Finished {name}")
    return f"Result from {name}"

async def async_with_return_value(x: int, y: int) -> int:
    """Async function that returns a value."""
    await asyncio.sleep(0.5)
    return x + y

# Async generators
async def async_generator(n: int):
    """Async generator that yields values."""
    for i in range(n):
        await asyncio.sleep(0.1)
        yield i * i

async def async_range(start: int, stop: int, step: int = 1):
    """Async range generator."""
    current = start
    while current < stop:
        await asyncio.sleep(0.05)
        yield current
        current += step

# Async context managers
class AsyncContextManager:
    """Async context manager example."""
    
    def __init__(self, name: str):
        self.name = name
    
    async def __aenter__(self):
        print(f"Entering {self.name}")
        await asyncio.sleep(0.1)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        print(f"Exiting {self.name}")
        await asyncio.sleep(0.1)

# Async iterators
class AsyncCounter:
    """Async iterator example."""
    
    def __init__(self, max_count: int):
        self.max_count = max_count
        self.current = 0
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self.current >= self.max_count:
            raise StopAsyncIteration
        
        await asyncio.sleep(0.1)
        value = self.current
        self.current += 1
        return value

# Concurrent execution
async def run_concurrent_tasks():
    """Demonstrate concurrent task execution."""
    tasks = [
        simple_async_function("Task 1"),
        simple_async_function("Task 2"),
        simple_async_function("Task 3")
    ]
    
    results = await asyncio.gather(*tasks)
    return results

async def run_with_timeout():
    """Demonstrate timeout handling."""
    try:
        result = await asyncio.wait_for(
            simple_async_function("Slow Task"),
            timeout=0.5
        )
        return result
    except asyncio.TimeoutError:
        return "Task timed out"

# Async with error handling
async def async_with_errors():
    """Demonstrate async error handling."""
    try:
        await asyncio.sleep(0.1)
        raise ValueError("Something went wrong")
    except ValueError as e:
        print(f"Caught error: {e}")
        return "Error handled"
    finally:
        print("Cleanup completed")

# Async data processing
@dataclass
class DataItem:
    """Data item for processing."""
    id: int
    value: str
    processed: bool = False

async def process_data_item(item: DataItem) -> DataItem:
    """Process a single data item asynchronously."""
    await asyncio.sleep(0.1)  # Simulate processing time
    item.processed = True
    item.value = item.value.upper()
    return item

async def process_data_batch(items: List[DataItem]) -> List[DataItem]:
    """Process a batch of data items concurrently."""
    tasks = [process_data_item(item) for item in items]
    return await asyncio.gather(*tasks)

# Async with semaphores (rate limiting)
async def worker_with_semaphore(semaphore: asyncio.Semaphore, worker_id: int):
    """Worker function that uses a semaphore for rate limiting."""
    async with semaphore:
        print(f"Worker {worker_id} starting")
        await asyncio.sleep(1)
        print(f"Worker {worker_id} finished")
        return f"Worker {worker_id} result"

async def run_with_semaphore():
    """Run multiple workers with semaphore limiting."""
    semaphore = asyncio.Semaphore(2)  # Allow only 2 concurrent workers
    tasks = [worker_with_semaphore(semaphore, i) for i in range(5)]
    return await asyncio.gather(*tasks)

# Async queues
async def producer(queue: asyncio.Queue, items: List[str]):
    """Producer that adds items to a queue."""
    for item in items:
        await asyncio.sleep(0.1)
        await queue.put(item)
        print(f"Produced: {item}")
    
    # Signal end of production
    await queue.put(None)

async def consumer(queue: asyncio.Queue, consumer_id: int):
    """Consumer that processes items from a queue."""
    while True:
        item = await queue.get()
        if item is None:
            break
        
        await asyncio.sleep(0.2)  # Simulate processing
        print(f"Consumer {consumer_id} processed: {item}")
        queue.task_done()

async def run_producer_consumer():
    """Run producer-consumer pattern."""
    queue = asyncio.Queue(maxsize=3)
    items = [f"item-{i}" for i in range(10)]
    
    # Start producer and consumers
    producer_task = asyncio.create_task(producer(queue, items))
    consumer_tasks = [
        asyncio.create_task(consumer(queue, i)) 
        for i in range(2)
    ]
    
    # Wait for producer to finish
    await producer_task
    
    # Wait for all items to be processed
    await queue.join()
    
    # Cancel consumers
    for task in consumer_tasks:
        task.cancel()

# Async with callbacks
def async_callback_example():
    """Demonstrate async callbacks."""
    async def async_callback(func: Callable[[], Awaitable[Any]]) -> Any:
        """Execute an async callback function."""
        return await func()
    
    async def callback_function() -> str:
        """Callback function to be executed."""
        await asyncio.sleep(0.1)
        return "Callback executed"
    
    return async_callback, callback_function

# Async class methods
class AsyncCalculator:
    """Class with async methods."""
    
    def __init__(self):
        self.history: List[str] = []
    
    async def add(self, a: float, b: float) -> float:
        """Async addition."""
        await asyncio.sleep(0.1)
        result = a + b
        self.history.append(f"Added {a} + {b} = {result}")
        return result
    
    async def multiply(self, a: float, b: float) -> float:
        """Async multiplication."""
        await asyncio.sleep(0.1)
        result = a * b
        self.history.append(f"Multiplied {a} * {b} = {result}")
        return result
    
    async def get_history(self) -> List[str]:
        """Get calculation history."""
        await asyncio.sleep(0.05)
        return self.history.copy()

# Async with external libraries (simulated)
async def simulate_http_request(url: str) -> Dict[str, Any]:
    """Simulate an HTTP request."""
    await asyncio.sleep(0.5)  # Simulate network delay
    return {
        "url": url,
        "status": 200,
        "data": f"Response from {url}",
        "timestamp": time.time()
    }

async def fetch_multiple_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """Fetch multiple URLs concurrently."""
    tasks = [simulate_http_request(url) for url in urls]
    return await asyncio.gather(*tasks)

# Complex async workflow
async def complex_workflow():
    """Demonstrate a complex async workflow."""
    print("Starting complex workflow")
    
    # Step 1: Initialize data
    data_items = [
        DataItem(1, "hello"),
        DataItem(2, "world"),
        DataItem(3, "async"),
        DataItem(4, "python")
    ]
    
    # Step 2: Process data concurrently
    processed_items = await process_data_batch(data_items)
    print(f"Processed {len(processed_items)} items")
    
    # Step 3: Simulate HTTP requests
    urls = ["http://api1.com", "http://api2.com", "http://api3.com"]
    responses = await fetch_multiple_urls(urls)
    print(f"Fetched {len(responses)} responses")
    
    # Step 4: Use async context manager
    async with AsyncContextManager("WorkflowContext"):
        await asyncio.sleep(0.1)
        print("Work completed in context")
    
    return {
        "processed_items": len(processed_items),
        "responses": len(responses),
        "status": "completed"
    }

# Main async function
async def main():
    """Main async function demonstrating various patterns."""
    print("=== Basic Async Functions ===")
    result1 = await simple_async_function("Basic Task")
    result2 = await async_with_return_value(5, 3)
    print(f"Results: {result1}, {result2}")
    
    print("\n=== Async Generators ===")
    async for value in async_generator(5):
        print(f"Generated: {value}")
    
    print("\n=== Async Iterators ===")
    async for count in AsyncCounter(3):
        print(f"Count: {count}")
    
    print("\n=== Concurrent Execution ===")
    concurrent_results = await run_concurrent_tasks()
    print(f"Concurrent results: {concurrent_results}")
    
    print("\n=== Timeout Handling ===")
    timeout_result = await run_with_timeout()
    print(f"Timeout result: {timeout_result}")
    
    print("\n=== Error Handling ===")
    error_result = await async_with_errors()
    print(f"Error result: {error_result}")
    
    print("\n=== Semaphore Rate Limiting ===")
    semaphore_results = await run_with_semaphore()
    print(f"Semaphore results: {semaphore_results}")
    
    print("\n=== Producer-Consumer ===")
    await run_producer_consumer()
    
    print("\n=== Async Callbacks ===")
    async_callback, callback_func = async_callback_example()
    callback_result = await async_callback(callback_func)
    print(f"Callback result: {callback_result}")
    
    print("\n=== Async Class Methods ===")
    calc = AsyncCalculator()
    sum_result = await calc.add(10, 5)
    product_result = await calc.multiply(3, 4)
    history = await calc.get_history()
    print(f"Sum: {sum_result}, Product: {product_result}")
    print(f"History: {history}")
    
    print("\n=== Complex Workflow ===")
    workflow_result = await complex_workflow()
    print(f"Workflow result: {workflow_result}")

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
