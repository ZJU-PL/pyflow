#!/usr/bin/env python3
"""
Type Annotations and Hints Example for PyFlow

This example demonstrates Python type annotations, type hints, and type checking
that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize type_annotations.py --analysis ipa
    pyflow callgraph type_annotations.py
"""

from typing import (
    List, Dict, Tuple, Set, Optional, Union, Any, Callable, 
    TypeVar, Generic, Protocol, Literal, Final, ClassVar
)
from dataclasses import dataclass
from enum import Enum
import sys

# Basic type annotations
def basic_types_example() -> str:
    """Demonstrate basic type annotations."""
    name: str = "Python"
    version: float = 3.9
    is_awesome: bool = True
    features: List[str] = ["typing", "dataclasses", "enums"]
    
    return f"{name} {version} is awesome: {is_awesome}"

def function_with_types(x: int, y: str) -> Tuple[int, str]:
    """Function with parameter and return type annotations."""
    return x * 2, y.upper()

# Optional and Union types
def optional_example(value: Optional[str] = None) -> Optional[int]:
    """Demonstrate Optional type usage."""
    if value is None:
        return None
    return len(value)

def union_example(value: Union[int, str, float]) -> str:
    """Demonstrate Union type usage."""
    if isinstance(value, int):
        return f"Integer: {value}"
    elif isinstance(value, str):
        return f"String: {value}"
    else:
        return f"Float: {value}"

# Generic types
T = TypeVar('T')

class Stack(Generic[T]):
    """Generic stack implementation."""
    
    def __init__(self) -> None:
        self._items: List[T] = []
    
    def push(self, item: T) -> None:
        """Push item onto stack."""
        self._items.append(item)
    
    def pop(self) -> Optional[T]:
        """Pop item from stack."""
        if not self._items:
            return None
        return self._items.pop()
    
    def peek(self) -> Optional[T]:
        """Peek at top item without removing."""
        if not self._items:
            return None
        return self._items[-1]
    
    def is_empty(self) -> bool:
        """Check if stack is empty."""
        return len(self._items) == 0

# Callable types
def callable_example() -> Callable[[int, int], int]:
    """Return a callable with type annotations."""
    def add(x: int, y: int) -> int:
        return x + y
    return add

def higher_order_function(func: Callable[[int], int], values: List[int]) -> List[int]:
    """Apply function to list of values."""
    return [func(x) for x in values]

# Protocol (structural typing)
class Drawable(Protocol):
    """Protocol for drawable objects."""
    
    def draw(self) -> str:
        """Draw the object."""
        ...

class Circle:
    """Circle class implementing Drawable protocol."""
    
    def __init__(self, radius: float) -> None:
        self.radius = radius
    
    def draw(self) -> str:
        return f"Drawing circle with radius {self.radius}"

class Rectangle:
    """Rectangle class implementing Drawable protocol."""
    
    def __init__(self, width: float, height: float) -> None:
        self.width = width
        self.height = height
    
    def draw(self) -> str:
        return f"Drawing rectangle {self.width}x{self.height}"

def draw_shapes(shapes: List[Drawable]) -> List[str]:
    """Draw a list of drawable shapes."""
    return [shape.draw() for shape in shapes]

# Enums with type annotations
class Color(Enum):
    """Color enumeration."""
    RED = "red"
    GREEN = "green"
    BLUE = "blue"
    YELLOW = "yellow"

def color_function(color: Color) -> str:
    """Function using enum type annotation."""
    return f"Selected color: {color.value}"

# Literal types
def literal_example(direction: Literal["up", "down", "left", "right"]) -> str:
    """Function using literal type annotation."""
    return f"Moving {direction}"

# Final and ClassVar
class Constants:
    """Class demonstrating Final and ClassVar."""
    
    # Class variable
    VERSION: ClassVar[str] = "1.0.0"
    
    # Final variable
    MAX_SIZE: Final[int] = 1000
    
    def __init__(self, name: str) -> None:
        self.name: str = name

# Dataclasses with type annotations
@dataclass
class Person:
    """Person dataclass with type annotations."""
    name: str
    age: int
    email: Optional[str] = None
    hobbies: List[str] = None
    
    def __post_init__(self) -> None:
        if self.hobbies is None:
            self.hobbies = []
    
    def is_adult(self) -> bool:
        """Check if person is adult."""
        return self.age >= 18
    
    def add_hobby(self, hobby: str) -> None:
        """Add a hobby to the person."""
        self.hobbies.append(hobby)

@dataclass
class Employee(Person):
    """Employee dataclass extending Person."""
    employee_id: str
    department: str
    salary: float
    
    def get_info(self) -> Dict[str, Union[str, int, float]]:
        """Get employee information as dictionary."""
        return {
            "name": self.name,
            "age": self.age,
            "employee_id": self.employee_id,
            "department": self.department,
            "salary": self.salary
        }

# Complex nested types
def complex_types_example() -> Dict[str, List[Tuple[str, int]]]:
    """Demonstrate complex nested type annotations."""
    data: Dict[str, List[Tuple[str, int]]] = {
        "fruits": [("apple", 5), ("banana", 3)],
        "vegetables": [("carrot", 10), ("potato", 8)]
    }
    return data

# Type aliases
UserId = int
UserName = str
UserData = Dict[str, Union[str, int, bool]]

def process_user(user_id: UserId, user_data: UserData) -> Tuple[UserId, UserName]:
    """Process user data using type aliases."""
    name = user_data.get("name", "Unknown")
    return user_id, name

# Generic functions
def find_item(items: List[T], predicate: Callable[[T], bool]) -> Optional[T]:
    """Find item in list using generic type."""
    for item in items:
        if predicate(item):
            return item
    return None

def map_items(items: List[T], func: Callable[[T], T]) -> List[T]:
    """Map function over list using generic type."""
    return [func(item) for item in items]

# Type checking with isinstance
def type_guards(value: Union[str, int, List[str]]) -> str:
    """Demonstrate type guards."""
    if isinstance(value, str):
        return f"String length: {len(value)}"
    elif isinstance(value, int):
        return f"Integer doubled: {value * 2}"
    elif isinstance(value, list):
        return f"List with {len(value)} items"
    else:
        return "Unknown type"

# Overloaded functions
from typing import overload

@overload
def process_data(data: int) -> str:
    """Process integer data."""
    ...

@overload
def process_data(data: str) -> int:
    """Process string data."""
    ...

@overload
def process_data(data: List[int]) -> List[str]:
    """Process list of integers."""
    ...

def process_data(data):
    """Process data with overloaded signatures."""
    if isinstance(data, int):
        return f"Number: {data}"
    elif isinstance(data, str):
        return len(data)
    elif isinstance(data, list):
        return [str(x) for x in data]
    else:
        raise TypeError("Unsupported data type")

# Type variables with constraints
Number = TypeVar('Number', int, float)

def add_numbers(a: Number, b: Number) -> Number:
    """Add two numbers of the same type."""
    return a + b

# Self type annotation (Python 3.11+)
if sys.version_info >= (3, 11):
    from typing import Self
    
    class Builder:
        """Builder class with Self type annotation."""
        
        def __init__(self, value: int = 0) -> None:
            self.value = value
        
        def add(self, n: int) -> Self:
            """Add to value and return self."""
            self.value += n
            return self
        
        def multiply(self, n: int) -> Self:
            """Multiply value and return self."""
            self.value *= n
            return self

if __name__ == "__main__":
    # Example usage
    print("=== Basic Types ===")
    result = basic_types_example()
    print(result)
    
    print("\n=== Function Types ===")
    num, text = function_with_types(5, "hello")
    print(f"Number: {num}, Text: {text}")
    
    print("\n=== Optional and Union ===")
    print(f"Optional None: {optional_example()}")
    print(f"Optional 'test': {optional_example('test')}")
    print(f"Union int: {union_example(42)}")
    print(f"Union str: {union_example('hello')}")
    print(f"Union float: {union_example(3.14)}")
    
    print("\n=== Generic Stack ===")
    int_stack = Stack[int]()
    int_stack.push(1)
    int_stack.push(2)
    print(f"Popped: {int_stack.pop()}")
    print(f"Peek: {int_stack.peek()}")
    
    str_stack = Stack[str]()
    str_stack.push("hello")
    str_stack.push("world")
    print(f"Popped: {str_stack.pop()}")
    
    print("\n=== Callable Types ===")
    add_func = callable_example()
    print(f"Add function: {add_func(3, 4)}")
    
    numbers = [1, 2, 3, 4, 5]
    doubled = higher_order_function(lambda x: x * 2, numbers)
    print(f"Doubled: {doubled}")
    
    print("\n=== Protocol Types ===")
    shapes = [Circle(5.0), Rectangle(10.0, 8.0)]
    drawings = draw_shapes(shapes)
    for drawing in drawings:
        print(drawing)
    
    print("\n=== Enum Types ===")
    print(color_function(Color.RED))
    print(color_function(Color.BLUE))
    
    print("\n=== Literal Types ===")
    print(literal_example("up"))
    print(literal_example("down"))
    
    print("\n=== Dataclasses ===")
    person = Person("Alice", 25, "alice@example.com")
    person.add_hobby("reading")
    person.add_hobby("coding")
    print(f"Person: {person.name}, Adult: {person.is_adult()}")
    print(f"Hobbies: {person.hobbies}")
    
    employee = Employee("Bob", 30, "bob@example.com", "EMP001", "Engineering", 75000.0)
    print(f"Employee info: {employee.get_info()}")
    
    print("\n=== Complex Types ===")
    complex_data = complex_types_example()
    print(f"Complex data: {complex_data}")
    
    print("\n=== Type Aliases ===")
    user_data = {"name": "Charlie", "age": 28, "active": True}
    user_id, user_name = process_user(123, user_data)
    print(f"User {user_id}: {user_name}")
    
    print("\n=== Generic Functions ===")
    numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    even = find_item(numbers, lambda x: x % 2 == 0)
    squared = map_items(numbers, lambda x: x * x)
    print(f"First even: {even}")
    print(f"Squared: {squared}")
    
    print("\n=== Type Guards ===")
    print(type_guards("hello"))
    print(type_guards(42))
    print(type_guards([1, 2, 3]))
    
    print("\n=== Overloaded Functions ===")
    print(f"Process int: {process_data(42)}")
    print(f"Process str: {process_data('hello')}")
    print(f"Process list: {process_data([1, 2, 3])}")
    
    print("\n=== Constrained Type Variables ===")
    print(f"Add ints: {add_numbers(5, 3)}")
    print(f"Add floats: {add_numbers(2.5, 1.5)}")
    
    if sys.version_info >= (3, 11):
        print("\n=== Self Type (Python 3.11+) ===")
        builder = Builder(10).add(5).multiply(2)
        print(f"Builder result: {builder.value}")
