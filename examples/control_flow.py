#!/usr/bin/env python3
"""
Control Flow Example for PyFlow

This example demonstrates control flow structures including conditionals,
loops, and branching that can be analyzed by PyFlow's control flow analysis.

Usage:
    pyflow optimize control_flow.py --analysis cpa
    pyflow callgraph control_flow.py
"""

def is_even(number):
    """Check if a number is even."""
    if number % 2 == 0:
        return True
    else:
        return False

def count_to_limit(limit):
    """Count from 1 to limit using a while loop."""
    count = 1
    while count <= limit:
        print(f"Count: {count}")
        count += 1
    return count - 1

def process_numbers(numbers):
    """Process a list of numbers with different operations."""
    results = []
    
    for num in numbers:
        if num < 0:
            # Skip negative numbers
            continue
        elif num == 0:
            # Special case for zero
            results.append("zero")
        elif is_even(num):
            # Even numbers: square them
            results.append(num * num)
        else:
            # Odd numbers: double them
            results.append(num * 2)
    
    return results

def find_maximum(numbers):
    """Find the maximum value in a list."""
    if not numbers:
        return None
    
    max_val = numbers[0]
    for i in range(1, len(numbers)):
        if numbers[i] > max_val:
            max_val = numbers[i]
    
    return max_val

def classify_temperature(temp):
    """Classify temperature into categories."""
    if temp < 0:
        return "freezing"
    elif temp < 10:
        return "cold"
    elif temp < 20:
        return "cool"
    elif temp < 30:
        return "warm"
    else:
        return "hot"

if __name__ == "__main__":
    # Example usage
    numbers = [1, 2, 3, 4, 5, -1, 0, 6]
    processed = process_numbers(numbers)
    maximum = find_maximum(numbers)
    temp_class = classify_temperature(25)
    
    print(f"Processed numbers: {processed}")
    print(f"Maximum: {maximum}")
    print(f"Temperature 25°C is: {temp_class}")
    
    count_to_limit(3)
