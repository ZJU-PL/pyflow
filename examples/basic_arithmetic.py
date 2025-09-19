#!/usr/bin/env python3
"""
Basic Arithmetic Example for PyFlow

This example demonstrates basic arithmetic operations and function calls
that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize basic_arithmetic.py
    pyflow callgraph basic_arithmetic.py
"""

def add_numbers(a, b):
    """Add two numbers and return the result."""
    return a + b

def multiply_numbers(x, y):
    """Multiply two numbers and return the result."""
    return x * y

def calculate_area(length, width):
    """Calculate the area of a rectangle."""
    return multiply_numbers(length, width)

def calculate_perimeter(length, width):
    """Calculate the perimeter of a rectangle."""
    return add_numbers(length, width) * 2

def math_operations(x, y):
    """Perform various math operations."""
    sum_result = add_numbers(x, y)
    product = multiply_numbers(x, y)
    area = calculate_area(x, y)
    perimeter = calculate_perimeter(x, y)
    
    return {
        'sum': sum_result,
        'product': product,
        'area': area,
        'perimeter': perimeter
    }

if __name__ == "__main__":
    # Example usage
    result = math_operations(5, 3)
    print(f"Math operations result: {result}")
