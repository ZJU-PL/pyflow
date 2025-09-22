#!/usr/bin/env python3
"""
Advanced OOP Patterns Example for PyFlow

This example demonstrates advanced OOP patterns including abstract classes,
mixins, descriptors, and metaclasses for static analysis testing.

Usage:
    pyflow optimize advanced_oop.py --analysis ipa
    pyflow callgraph advanced_oop.py
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
import functools

# Abstract base classes
class Shape(ABC):
    """Abstract base class for geometric shapes."""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    def area(self) -> float:
        """Calculate area."""
        pass
    
    @abstractmethod
    def perimeter(self) -> float:
        """Calculate perimeter."""
        pass

class Circle(Shape):
    """Circle implementation."""
    
    def __init__(self, name: str, radius: float):
        super().__init__(name)
        self.radius = radius
    
    def area(self) -> float:
        import math
        return math.pi * self.radius ** 2
    
    def perimeter(self) -> float:
        import math
        return 2 * math.pi * self.radius

# Mixins
class DrawableMixin:
    """Mixin for drawable objects."""
    
    def draw(self) -> str:
        return f"Drawing {self.__class__.__name__}: {self.name}"

class ColorableMixin:
    """Mixin for colorable objects."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._color = "black"
    
    @property
    def color(self) -> str:
        return self._color
    
    @color.setter
    def color(self, value: str):
        self._color = value

# Multiple inheritance with mixins
class ColoredDrawableCircle(Circle, DrawableMixin, ColorableMixin):
    """Circle with drawing and coloring capabilities."""
    
    def draw(self) -> str:
        return f"Drawing {self.color} circle: {self.name}"

# Descriptors
class ValidatedAttribute:
    """Descriptor for validated attributes."""
    
    def __init__(self, validator: Callable[[Any], bool]):
        self.validator = validator
        self.name = None
    
    def __set_name__(self, owner, name):
        self.name = name
    
    def __get__(self, instance, owner):
        if instance is None:
            return self
        return instance.__dict__.get(self.name)
    
    def __set__(self, instance, value):
        if not self.validator(value):
            raise ValueError(f"Invalid value for {self.name}")
        instance.__dict__[self.name] = value

class PositiveNumber(ValidatedAttribute):
    """Descriptor for positive numbers."""
    
    def __init__(self):
        super().__init__(lambda x: isinstance(x, (int, float)) and x > 0)

# Class using descriptors
class Person:
    """Person class with validated attributes."""
    
    name = ValidatedAttribute(lambda x: isinstance(x, str) and len(x) > 0)
    age = PositiveNumber()
    
    def __init__(self, name: str, age: int):
        self.name = name
        self.age = age

# Metaclasses
class SingletonMeta(type):
    """Metaclass for singleton pattern."""
    _instances = {}
    
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class Database(metaclass=SingletonMeta):
    """Database class using singleton metaclass."""
    
    def __init__(self):
        self.connections = 0
    
    def connect(self):
        self.connections += 1
        return f"Connected (total: {self.connections})"

# Property decorators
class Temperature:
    """Temperature class with property decorators."""
    
    def __init__(self, celsius: float = 0):
        self._celsius = celsius
    
    @property
    def celsius(self) -> float:
        return self._celsius
    
    @celsius.setter
    def celsius(self, value: float) -> None:
        if value < -273.15:
            raise ValueError("Temperature cannot be below absolute zero")
        self._celsius = value
    
    @property
    def fahrenheit(self) -> float:
        return self._celsius * 9/5 + 32

if __name__ == "__main__":
    # Test abstract classes
    circle = Circle("MyCircle", 5.0)
    print(f"Circle area: {circle.area()}")
    
    # Test mixins
    colored_circle = ColoredDrawableCircle("ColoredCircle", 3.0)
    colored_circle.color = "red"
    print(colored_circle.draw())
    
    # Test descriptors
    person = Person("Alice", 30)
    print(f"Person: {person.name}, {person.age}")
    
    # Test metaclasses
    db1 = Database()
    db2 = Database()
    print(f"Same database: {db1 is db2}")
    
    # Test properties
    temp = Temperature(25.0)
    print(f"25°C = {temp.fahrenheit}°F")
