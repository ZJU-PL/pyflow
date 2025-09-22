#!/usr/bin/env python3
"""
Advanced Typing Features Example for PyFlow

This example demonstrates advanced Python typing features including TypedDict,
NewType, ParamSpec, and other modern typing constructs for static analysis testing.

Usage:
    pyflow optimize advanced_typing.py --analysis ipa
    pyflow callgraph advanced_typing.py
"""

import sys
from typing import (
    Dict, List, Tuple, Optional, Union, Any, Callable, TypeVar, Generic,
    TypedDict, NewType, Literal, Final, ClassVar, Protocol, runtime_checkable,
    ParamSpec, TypeGuard, cast
)

# TypedDict examples
class UserData(TypedDict):
    """TypedDict for user data."""
    name: str
    age: int
    email: str
    is_active: bool

class UserProfile(TypedDict, total=False):
    """TypedDict with optional fields."""
    user_id: int
    username: str
    bio: str

def process_user_data(user: UserData) -> str:
    """Process user data using TypedDict."""
    return f"User: {user['name']}, Age: {user['age']}, Active: {user['is_active']}"

# NewType examples
UserId = NewType('UserId', int)
ProductId = NewType('ProductId', int)

def process_user_id(user_id: UserId) -> str:
    """Process user ID using NewType."""
    return f"Processing user: {user_id}"

def create_user_id(value: int) -> UserId:
    """Create UserId from int."""
    return UserId(value)

# Literal types
Status = Literal["pending", "approved", "rejected", "cancelled"]
Priority = Literal["low", "medium", "high", "critical"]

def process_status(status: Status) -> str:
    """Process status using Literal type."""
    status_messages = {
        "pending": "Request is pending review",
        "approved": "Request has been approved",
        "rejected": "Request has been rejected",
        "cancelled": "Request has been cancelled"
    }
    return status_messages[status]

# Final and ClassVar
class Configuration:
    """Configuration class with Final and ClassVar."""
    
    VERSION: ClassVar[str] = "1.0.0"
    MAX_CONNECTIONS: ClassVar[int] = 100
    
    API_KEY: Final[str] = "secret-key-12345"
    
    def __init__(self, environment: str):
        self.environment: str = environment

# Protocol examples
@runtime_checkable
class Drawable(Protocol):
    """Protocol for drawable objects."""
    
    def draw(self) -> str:
        """Draw the object."""
        ...
    
    def get_area(self) -> float:
        """Get the area of the object."""
        ...

class Circle:
    """Circle class implementing Drawable protocol."""
    
    def __init__(self, radius: float):
        self.radius = radius
    
    def draw(self) -> str:
        return f"Drawing circle with radius {self.radius}"
    
    def get_area(self) -> float:
        import math
        return math.pi * self.radius ** 2

def draw_objects(objects: List[Drawable]) -> List[str]:
    """Draw a list of drawable objects."""
    return [obj.draw() for obj in objects]

# ParamSpec for preserving function signatures
P = ParamSpec('P')
T = TypeVar('T')

def timing_decorator(func: Callable[P, T]) -> Callable[P, T]:
    """Decorator that preserves function signature using ParamSpec."""
    import functools
    
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        import time
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

@timing_decorator
def slow_function(x: int, y: str) -> str:
    """Slow function for testing timing decorator."""
    import time
    time.sleep(0.1)
    return f"Result: {x} + {y}"

# Type guards
def is_string_list(value: List[Any]) -> TypeGuard[List[str]]:
    """Type guard to check if list contains only strings."""
    return all(isinstance(item, str) for item in value)

def process_data(data: List[Any]) -> List[str]:
    """Process data using type guards."""
    if is_string_list(data):
        # Type checker knows data is List[str] here
        return [item.upper() for item in data]
    else:
        return [str(item) for item in data]

# Generic classes with constraints
Number = TypeVar('Number', int, float)

class Calculator(Generic[Number]):
    """Generic calculator for numbers."""
    
    def __init__(self, initial_value: Number = 0):
        self.value = initial_value
    
    def add(self, other: Number) -> 'Calculator[Number]':
        """Add number to calculator."""
        return Calculator(self.value + other)
    
    def get_value(self) -> Number:
        """Get current value."""
        return self.value

# Overloaded functions
from typing import overload

@overload
def process_item(item: int) -> str:
    """Process integer item."""
    ...

@overload
def process_item(item: str) -> int:
    """Process string item."""
    ...

def process_item(item):
    """Process item with overloaded signatures."""
    if isinstance(item, int):
        return f"Number: {item}"
    elif isinstance(item, str):
        return len(item)
    else:
        raise TypeError("Unsupported item type")

# Type variables with constraints
def add_numbers(a: Number, b: Number) -> Number:
    """Add two numbers of the same type."""
    return a + b

if __name__ == "__main__":
    print("=== TypedDict Examples ===")
    user_data: UserData = {
        "name": "Alice",
        "age": 30,
        "email": "alice@example.com",
        "is_active": True
    }
    print(process_user_data(user_data))
    
    print("\n=== NewType Examples ===")
    user_id = create_user_id(12345)
    print(process_user_id(user_id))
    
    print("\n=== Literal Types ===")
    print(process_status("approved"))
    
    print("\n=== Final and ClassVar ===")
    config = Configuration("production")
    print(f"Version: {Configuration.VERSION}")
    print(f"API Key: {config.API_KEY}")
    
    print("\n=== Protocol Types ===")
    circle = Circle(5.0)
    print(circle.draw())
    print(f"Area: {circle.get_area()}")
    print(f"Is Drawable: {isinstance(circle, Drawable)}")
    
    print("\n=== ParamSpec Examples ===")
    result = slow_function(42, "hello")
    print(result)
    
    print("\n=== Type Guards ===")
    string_list = ["hello", "world", "python"]
    number_list = [1, 2, 3, 4, 5]
    
    print(f"String list: {process_data(string_list)}")
    print(f"Number list: {process_data(number_list)}")
    
    print("\n=== Generic Calculator ===")
    int_calc = Calculator[int](10)
    int_result = int_calc.add(5)
    print(f"Int calculator: {int_result.get_value()}")
    
    float_calc = Calculator[float](3.14)
    float_result = float_calc.add(1.86)
    print(f"Float calculator: {float_result.get_value()}")
    
    print("\n=== Overloaded Functions ===")
    print(f"Process int: {process_item(42)}")
    print(f"Process str: {process_item('hello')}")
    
    print("\n=== Constrained Type Variables ===")
    print(f"Add ints: {add_numbers(5, 3)}")
    print(f"Add floats: {add_numbers(2.5, 1.5)}")
