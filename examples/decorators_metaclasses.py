#!/usr/bin/env python3
"""
Decorators and Metaclasses Example for PyFlow

This example demonstrates Python decorators, metaclasses, and advanced
object-oriented features that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize decorators_metaclasses.py --analysis ipa
    pyflow callgraph decorators_metaclasses.py
"""

import functools
import time
from typing import Any, Callable, Dict, List

# Simple decorators
def timing_decorator(func):
    """Decorator to measure function execution time."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} took {end_time - start_time:.4f} seconds")
        return result
    return wrapper

def retry_decorator(max_attempts=3):
    """Decorator factory for retrying functions."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    print(f"Attempt {attempt + 1} failed: {e}")
                    if attempt == max_attempts - 1:
                        raise last_exception
            return None
        return wrapper
    return decorator

def memoize(func):
    """Memoization decorator to cache function results."""
    cache = {}
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        key = str(args) + str(sorted(kwargs.items()))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]
    return wrapper

# Class decorators
def singleton(cls):
    """Singleton decorator for classes."""
    instances = {}
    
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    
    return get_instance

def add_method(cls):
    """Decorator to add methods to a class."""
    def new_method(self):
        return f"Added method in {self.__class__.__name__}"
    
    cls.new_method = new_method
    return cls

# Property decorators
class Temperature:
    """Class demonstrating property decorators."""
    
    def __init__(self, celsius=0):
        self._celsius = celsius
    
    @property
    def celsius(self):
        """Get temperature in Celsius."""
        return self._celsius
    
    @celsius.setter
    def celsius(self, value):
        """Set temperature in Celsius."""
        if value < -273.15:
            raise ValueError("Temperature cannot be below absolute zero")
        self._celsius = value
    
    @property
    def fahrenheit(self):
        """Get temperature in Fahrenheit."""
        return self._celsius * 9/5 + 32
    
    @fahrenheit.setter
    def fahrenheit(self, value):
        """Set temperature in Fahrenheit."""
        self.celsius = (value - 32) * 5/9

# Metaclasses
class SingletonMeta(type):
    """Metaclass for singleton pattern."""
    _instances = {}
    
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class AutoRegisterMeta(type):
    """Metaclass that automatically registers classes."""
    registry = {}
    
    def __new__(mcs, name, bases, attrs):
        cls = super().__new__(mcs, name, bases, attrs)
        if name != 'BasePlugin':
            mcs.registry[name] = cls
        return cls

class ValidationMeta(type):
    """Metaclass that adds validation to class attributes."""
    
    def __new__(mcs, name, bases, attrs):
        # Add validation methods
        attrs['_validate_attributes'] = mcs._validate_attributes
        return super().__new__(mcs, name, bases, attrs)
    
    @staticmethod
    def _validate_attributes(self):
        """Validate all attributes with type hints."""
        for attr_name, attr_value in self.__dict__.items():
            if hasattr(self.__class__, attr_name):
                annotation = self.__class__.__annotations__.get(attr_name)
                if annotation and not isinstance(attr_value, annotation):
                    raise TypeError(f"{attr_name} must be of type {annotation}")

# Classes using metaclasses
class Database(metaclass=SingletonMeta):
    """Database class using singleton metaclass."""
    
    def __init__(self):
        self.connections = 0
    
    def connect(self):
        self.connections += 1
        return f"Connected (total: {self.connections})"

class BasePlugin(metaclass=AutoRegisterMeta):
    """Base plugin class that gets auto-registered."""
    pass

class MathPlugin(BasePlugin):
    """Math operations plugin."""
    
    def add(self, a, b):
        return a + b

class StringPlugin(BasePlugin):
    """String operations plugin."""
    
    def upper(self, text):
        return text.upper()

class ValidatedClass(metaclass=ValidationMeta):
    """Class with attribute validation."""
    
    name: str
    age: int
    active: bool
    
    def __init__(self, name, age, active):
        self.name = name
        self.age = age
        self.active = active
        self._validate_attributes()

# Advanced decorator patterns
def class_decorator(decorator_func):
    """Decorator that can be applied to classes."""
    def decorator(cls):
        for attr_name in dir(cls):
            attr = getattr(cls, attr_name)
            if callable(attr) and not attr_name.startswith('_'):
                setattr(cls, attr_name, decorator_func(attr))
        return cls
    return decorator

@class_decorator(timing_decorator)
class Calculator:
    """Calculator class with all methods decorated."""
    
    def add(self, a, b):
        return a + b
    
    def multiply(self, a, b):
        return a * b
    
    def divide(self, a, b):
        if b == 0:
            raise ValueError("Division by zero")
        return a / b

# Context manager decorator
def context_manager(func):
    """Decorator to turn a generator into a context manager."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return ContextManager(func(*args, **kwargs))
    return wrapper

class ContextManager:
    """Context manager wrapper."""
    
    def __init__(self, gen):
        self.gen = gen
    
    def __enter__(self):
        return next(self.gen)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            next(self.gen)
        except StopIteration:
            pass

@context_manager
def file_context(filename):
    """Context manager for file operations."""
    print(f"Opening {filename}")
    file_handle = open(filename, 'w')
    try:
        yield file_handle
    finally:
        print(f"Closing {filename}")
        file_handle.close()

# Decorator with arguments and state
def stateful_decorator(initial_state=0):
    """Decorator that maintains state across calls."""
    def decorator(func):
        state = {'value': initial_state}
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            state['value'] += 1
            print(f"Call #{state['value']} of {func.__name__}")
            return func(*args, **kwargs)
        
        wrapper.get_state = lambda: state['value']
        wrapper.reset_state = lambda: state.update({'value': initial_state})
        return wrapper
    return decorator

@stateful_decorator(10)
def counter_function():
    """Function that tracks how many times it's called."""
    return "Called"

if __name__ == "__main__":
    # Example usage
    print("=== Simple Decorators ===")
    
    @timing_decorator
    @memoize
    def fibonacci(n):
        if n <= 1:
            return n
        return fibonacci(n-1) + fibonacci(n-2)
    
    result = fibonacci(10)
    print(f"Fibonacci(10) = {result}")
    
    print("\n=== Retry Decorator ===")
    
    @retry_decorator(3)
    def unreliable_function():
        import random
        if random.random() < 0.7:
            raise Exception("Random failure")
        return "Success!"
    
    try:
        result = unreliable_function()
        print(f"Result: {result}")
    except Exception as e:
        print(f"All attempts failed: {e}")
    
    print("\n=== Singleton Decorator ===")
    
    @singleton
    class Config:
        def __init__(self):
            self.value = 42
    
    config1 = Config()
    config2 = Config()
    print(f"Same instance: {config1 is config2}")
    
    print("\n=== Property Decorators ===")
    temp = Temperature(25)
    print(f"25°C = {temp.fahrenheit}°F")
    temp.fahrenheit = 100
    print(f"100°F = {temp.celsius}°C")
    
    print("\n=== Metaclass Examples ===")
    db1 = Database()
    db2 = Database()
    print(f"Same database: {db1 is db2}")
    print(db1.connect())
    
    print("\n=== Auto-registration ===")
    print(f"Registered plugins: {list(AutoRegisterMeta.registry.keys())}")
    
    print("\n=== Validation Metaclass ===")
    try:
        valid_obj = ValidatedClass("John", 25, True)
        print(f"Valid object: {valid_obj.name}, {valid_obj.age}, {valid_obj.active}")
    except TypeError as e:
        print(f"Validation error: {e}")
    
    print("\n=== Class Decorator ===")
    calc = Calculator()
    print(f"2 + 3 = {calc.add(2, 3)}")
    print(f"2 * 3 = {calc.multiply(2, 3)}")
    
    print("\n=== Stateful Decorator ===")
    print(counter_function())
    print(counter_function())
    print(f"State: {counter_function.get_state()}")
    counter_function.reset_state()
    print(f"After reset: {counter_function.get_state()}")
    
    print("\n=== Context Manager Decorator ===")
    with file_context("test.txt") as f:
        f.write("Hello, World!")
    print("File written and closed")
