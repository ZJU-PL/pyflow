"""
Utilities for asynchronous function execution using threading.

This module provides decorators to execute functions asynchronously in separate
threads, with optional concurrency limiting using semaphores.
"""

__all__ = ["async_func", "async_limited"]

import threading
import functools

# Global flag to enable/disable async execution
# When False, decorated functions execute synchronously
enabled = True


def async_func(func):
    """Decorator to execute a function asynchronously in a separate thread.

    When applied to a function, calls to that function will be executed in a
    background thread and return immediately with the thread object. This is
    useful for non-blocking execution of potentially long-running operations.

    Args:
        func: The function to be executed asynchronously.

    Returns:
        If `enabled` is True, returns a wrapper function that spawns a thread.
        If `enabled` is False, returns the original function unchanged.

    Example:
        @async_func
        def long_running_task():
            # ... do work ...
            pass

        thread = long_running_task()  # Returns immediately
        thread.join()  # Wait for completion
    """
    @functools.wraps(func)
    def async_wrapper(*args, **kargs):
        t = threading.Thread(target=func, args=args, kwargs=kargs)
        t.start()
        return t

    if enabled:
        return async_wrapper
    else:
        return func


def async_limited(count):
    """Decorator factory for async execution with concurrency limiting.

    Creates a decorator that limits the number of concurrent executions of
    a function to a specified maximum. Uses a bounded semaphore to enforce
    the limit.

    Args:
        count: Maximum number of concurrent executions allowed.

    Returns:
        A decorator function that can be applied to functions.

    Example:
        @async_limited(3)
        def api_call():
            # ... make API request ...
            pass

        # Only 3 instances of api_call can run concurrently
        for i in range(10):
            api_call()  # First 3 start immediately, others wait
    """
    def limited_func(func):
        # Semaphore to limit concurrent executions
        semaphore = threading.BoundedSemaphore(count)

        # Inner wrapper that releases semaphore after function completes
        def thread_wrap(*args, **kargs):
            result = func(*args, **kargs)
            semaphore.release()
            return result

        # Outer wrapper that acquires semaphore before spawning thread
        @functools.wraps(func)
        def limited_wrap(*args, **kargs):
            semaphore.acquire()
            t = threading.Thread(target=thread_wrap, args=args, kwargs=kargs)
            t.start()
            return t

        if enabled:
            return limited_wrap
        else:
            return func

    return limited_func
