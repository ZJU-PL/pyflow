#!/usr/bin/env python3
"""
Lambda Functions and Closures Example for PyFlow

This example demonstrates lambda functions, closures, and functional programming
concepts that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize lambda_closures.py --analysis ipa
    pyflow callgraph lambda_closures.py
"""

import functools
from typing import Callable, List, Any

# Basic lambda functions
def basic_lambdas():
    """Demonstrate basic lambda function usage."""
    # Simple arithmetic
    add = lambda x, y: x + y
    multiply = lambda x, y: x * y
    square = lambda x: x ** 2
    
    # Conditional expressions
    absolute = lambda x: x if x >= 0 else -x
    max_value = lambda x, y: x if x > y else y
    
    # String operations
    upper = lambda s: s.upper()
    reverse = lambda s: s[::-1]
    
    return add(5, 3), multiply(4, 6), square(7), absolute(-10), max_value(15, 8), upper("hello"), reverse("world")

# Lambda with higher-order functions
def higher_order_lambdas():
    """Demonstrate lambdas with higher-order functions."""
    numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    
    # Map with lambda
    squares = list(map(lambda x: x ** 2, numbers))
    
    # Filter with lambda
    evens = list(filter(lambda x: x % 2 == 0, numbers))
    
    # Reduce with lambda
    from functools import reduce
    sum_all = reduce(lambda x, y: x + y, numbers)
    
    # Sorted with lambda
    words = ["apple", "banana", "cherry", "date"]
    by_length = sorted(words, key=lambda x: len(x))
    
    return squares, evens, sum_all, by_length

# Closures
def create_multiplier(factor):
    """Create a closure that multiplies by a factor."""
    def multiplier(x):
        return x * factor
    return multiplier

def create_counter(initial=0):
    """Create a closure that maintains state."""
    count = initial
    
    def counter():
        nonlocal count
        count += 1
        return count
    
    def reset():
        nonlocal count
        count = initial
    
    def get_count():
        return count
    
    # Return multiple functions
    counter.reset = reset
    counter.get_count = get_count
    return counter

def create_accumulator():
    """Create an accumulator closure."""
    total = 0
    
    def add(value):
        nonlocal total
        total += value
        return total
    
    def get_total():
        return total
    
    def reset():
        nonlocal total
        total = 0
    
    add.get_total = get_total
    add.reset = reset
    return add

# Advanced closure patterns
def create_validator(rules):
    """Create a validator closure with multiple rules."""
    def validate(value):
        for rule_name, rule_func in rules.items():
            if not rule_func(value):
                return False, f"Failed rule: {rule_name}"
        return True, "Valid"
    return validate

def create_cached_function(func):
    """Create a memoized version of a function using closure."""
    cache = {}
    
    def cached_func(*args, **kwargs):
        key = str(args) + str(sorted(kwargs.items()))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]
    
    cached_func.cache = cache
    cached_func.clear_cache = lambda: cache.clear()
    return cached_func

# Lambda with complex data structures
def complex_lambda_operations():
    """Demonstrate complex lambda operations on data structures."""
    people = [
        {"name": "Alice", "age": 30, "city": "New York"},
        {"name": "Bob", "age": 25, "city": "Boston"},
        {"name": "Charlie", "age": 35, "city": "New York"},
        {"name": "Diana", "age": 28, "city": "Chicago"}
    ]
    
    # Filter by age
    young_people = list(filter(lambda p: p["age"] < 30, people))
    
    # Map to names
    names = list(map(lambda p: p["name"], people))
    
    # Sort by age
    by_age = sorted(people, key=lambda p: p["age"])
    
    # Group by city (simplified)
    by_city = {}
    for person in people:
        city = person["city"]
        if city not in by_city:
            by_city[city] = []
        by_city[city].append(person["name"])
    
    # Find oldest person
    oldest = max(people, key=lambda p: p["age"])
    
    return young_people, names, by_age, by_city, oldest

# Nested lambdas and closures
def nested_lambda_example():
    """Demonstrate nested lambdas and complex closures."""
    def create_math_operations():
        """Create a set of math operations using closures."""
        operations = {}
        
        # Addition
        operations['add'] = lambda x, y: x + y
        
        # Multiplication
        operations['multiply'] = lambda x, y: x * y
        
        # Power (using nested lambda)
        operations['power'] = lambda base: lambda exp: base ** exp
        
        # Factorial (recursive lambda)
        operations['factorial'] = lambda n: 1 if n <= 1 else n * operations['factorial'](n - 1)
        
        return operations
    
    def create_function_composer():
        """Create a function composer using closures."""
        functions = []
        
        def add_function(func):
            functions.append(func)
            return add_function
        
        def compose():
            def composed(x):
                result = x
                for func in functions:
                    result = func(result)
                return result
            return composed
        
        add_function.compose = compose
        return add_function
    
    return create_math_operations(), create_function_composer()

# Lambda with exception handling
def lambda_with_exceptions():
    """Demonstrate lambda functions with exception handling."""
    def safe_divide():
        return lambda x, y: x / y if y != 0 else float('inf')
    
    def safe_operation(operation):
        return lambda *args: operation(*args) if args else None
    
    # Safe operations
    safe_div = safe_divide()
    safe_add = safe_operation(lambda x, y: x + y)
    
    return safe_div(10, 2), safe_div(10, 0), safe_add(5, 3), safe_add()

# Lambda in class methods
class LambdaContainer:
    """Class demonstrating lambda usage in methods."""
    
    def __init__(self, data):
        self.data = data
    
    def process_with_lambda(self, operation):
        """Process data using a lambda operation."""
        return [operation(item) for item in self.data]
    
    def filter_with_lambda(self, predicate):
        """Filter data using a lambda predicate."""
        return [item for item in self.data if predicate(item)]
    
    def create_processor(self, factor):
        """Create a processor closure."""
        def processor(x):
            return x * factor
        return processor

# Advanced functional programming patterns
def functional_patterns():
    """Demonstrate advanced functional programming patterns."""
    def curry(func):
        """Curry a function."""
        def curried(*args):
            if len(args) >= func.__code__.co_argcount:
                return func(*args)
            return lambda *more_args: curried(*(args + more_args))
        return curried
    
    def compose(*functions):
        """Compose multiple functions."""
        def composed(x):
            result = x
            for func in reversed(functions):
                result = func(result)
            return result
        return composed
    
    def partial_application(func, *args):
        """Partial application of function arguments."""
        return lambda *more_args: func(*(args + more_args))
    
    # Example usage
    add_three = curry(lambda x, y, z: x + y + z)
    add_one_two = add_three(1)(2)
    
    square = lambda x: x ** 2
    double = lambda x: x * 2
    composed_func = compose(square, double)
    
    add_five = partial_application(lambda x, y: x + y, 5)
    
    return add_one_two(3), composed_func(4), add_five(10)

if __name__ == "__main__":
    # Example usage
    print("=== Basic Lambdas ===")
    add, mult, sq, abs_val, max_val, upper, rev = basic_lambdas()
    print(f"5 + 3 = {add}")
    print(f"4 * 6 = {mult}")
    print(f"7² = {sq}")
    print(f"|-10| = {abs_val}")
    print(f"max(15, 8) = {max_val}")
    print(f"'hello'.upper() = {upper}")
    print(f"'world' reversed = {rev}")
    
    print("\n=== Higher-Order Lambdas ===")
    squares, evens, sum_all, by_length = higher_order_lambdas()
    print(f"Squares: {squares}")
    print(f"Evens: {evens}")
    print(f"Sum: {sum_all}")
    print(f"By length: {by_length}")
    
    print("\n=== Closures ===")
    double = create_multiplier(2)
    triple = create_multiplier(3)
    print(f"Double 5: {double(5)}")
    print(f"Triple 5: {triple(5)}")
    
    counter = create_counter(10)
    print(f"Counter: {counter()}, {counter()}, {counter()}")
    print(f"Count: {counter.get_count()}")
    counter.reset()
    print(f"After reset: {counter()}")
    
    acc = create_accumulator()
    print(f"Accumulator: {acc(5)}, {acc(3)}, {acc(2)}")
    print(f"Total: {acc.get_total()}")
    
    print("\n=== Complex Lambda Operations ===")
    young, names, by_age, by_city, oldest = complex_lambda_operations()
    print(f"Young people: {young}")
    print(f"Names: {names}")
    print(f"Oldest: {oldest}")
    print(f"By city: {by_city}")
    
    print("\n=== Nested Lambdas ===")
    math_ops, composer = nested_lambda_example()
    print(f"2^3 = {math_ops['power'](2)(3)}")
    print(f"5! = {math_ops['factorial'](5)}")
    
    add_func = composer(lambda x: x + 1)(lambda x: x * 2)
    composed = add_func.compose()
    print(f"Composed(5): {composed(5)}")
    
    print("\n=== Lambda with Exceptions ===")
    div_result, inf_result, add_result, none_result = lambda_with_exceptions()
    print(f"10/2 = {div_result}")
    print(f"10/0 = {inf_result}")
    print(f"5+3 = {add_result}")
    print(f"add() = {none_result}")
    
    print("\n=== Lambda in Classes ===")
    container = LambdaContainer([1, 2, 3, 4, 5])
    processed = container.process_with_lambda(lambda x: x * 2)
    filtered = container.filter_with_lambda(lambda x: x % 2 == 0)
    processor = container.create_processor(3)
    print(f"Processed: {processed}")
    print(f"Filtered: {filtered}")
    print(f"Processor(4): {processor(4)}")
    
    print("\n=== Functional Patterns ===")
    curry_result, compose_result, partial_result = functional_patterns()
    print(f"Curried add: {curry_result}")
    print(f"Composed: {compose_result}")
    print(f"Partial: {partial_result}")
