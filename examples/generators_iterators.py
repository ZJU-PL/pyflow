#!/usr/bin/env python3
"""
Generators and Iterators Example for PyFlow

This example demonstrates Python generators, iterators, and iteration protocols
that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize generators_iterators.py --analysis ipa
    pyflow callgraph generators_iterators.py
"""

def simple_generator(n):
    """A simple generator function."""
    for i in range(n):
        yield i * i

def fibonacci_generator(limit):
    """Generate Fibonacci numbers up to a limit."""
    a, b = 0, 1
    while a < limit:
        yield a
        a, b = b, a + b

def read_file_lines(filename):
    """Generator to read file lines lazily."""
    try:
        with open(filename, 'r') as file:
            for line in file:
                yield line.strip()
    except FileNotFoundError:
        yield "File not found"

def batch_processor(data, batch_size):
    """Process data in batches using a generator."""
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        yield process_batch(batch)

def process_batch(batch):
    """Process a single batch of data."""
    return sum(batch) if batch else 0

class NumberSequence:
    """Custom iterator class implementing the iterator protocol."""
    
    def __init__(self, start, end, step=1):
        self.start = start
        self.end = end
        self.step = step
        self.current = start
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self.current >= self.end:
            raise StopIteration
        value = self.current
        self.current += self.step
        return value

class TreeIterator:
    """Iterator for traversing a binary tree."""
    
    def __init__(self, root):
        self.stack = []
        self.current = root
    
    def __iter__(self):
        return self
    
    def __next__(self):
        while self.current or self.stack:
            if self.current:
                self.stack.append(self.current)
                self.current = self.current.left
            else:
                self.current = self.stack.pop()
                value = self.current.value
                self.current = self.current.right
                return value
        raise StopIteration

class TreeNode:
    """Simple tree node for iterator example."""
    def __init__(self, value, left=None, right=None):
        self.value = value
        self.left = left
        self.right = right

def generator_expression_example():
    """Demonstrate generator expressions."""
    numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    
    # Generator expression for squares
    squares = (x * x for x in numbers if x % 2 == 0)
    
    # Generator expression for filtering
    evens = (x for x in numbers if x % 2 == 0)
    
    return list(squares), list(evens)

def nested_generators():
    """Demonstrate nested generators and generator composition."""
    def inner_gen(n):
        for i in range(n):
            yield i * 2
    
    def outer_gen(n):
        for i in range(n):
            yield from inner_gen(i + 1)
    
    return list(outer_gen(3))

def generator_with_send():
    """Demonstrate generator with send() method."""
    def accumulator():
        total = 0
        while True:
            value = yield total
            if value is not None:
                total += value
    
    acc = accumulator()
    next(acc)  # Start the generator
    
    results = []
    for i in [1, 2, 3, 4, 5]:
        result = acc.send(i)
        results.append(result)
    
    return results

def generator_with_throw():
    """Demonstrate generator with throw() method."""
    def error_generator():
        try:
            while True:
                value = yield
                if value < 0:
                    raise ValueError("Negative value not allowed")
                yield value * 2
        except ValueError as e:
            yield f"Error: {e}"
    
    gen = error_generator()
    next(gen)  # Start the generator
    
    results = []
    for value in [1, 2, -3, 4]:
        try:
            gen.send(value)
            result = next(gen)
            results.append(result)
        except StopIteration:
            break
    
    return results

def itertools_style_generators():
    """Implement itertools-style generator functions."""
    def count(start=0, step=1):
        """Count from start with given step."""
        while True:
            yield start
            start += step
    
    def cycle(iterable):
        """Cycle through an iterable indefinitely."""
        while True:
            for item in iterable:
                yield item
    
    def take(n, iterable):
        """Take first n items from iterable."""
        for i, item in enumerate(iterable):
            if i >= n:
                break
            yield item
    
    def dropwhile(predicate, iterable):
        """Drop items while predicate is true."""
        dropping = True
        for item in iterable:
            if dropping and predicate(item):
                continue
            dropping = False
            yield item
    
    return count, cycle, take, dropwhile

def memory_efficient_processing():
    """Demonstrate memory-efficient processing with generators."""
    def process_large_dataset(filename):
        """Process a large dataset without loading it all into memory."""
        with open(filename, 'w') as f:
            # Generate test data
            for i in range(1000):
                f.write(f"Line {i}: Data {i * i}\n")
        
        # Process line by line
        processed_count = 0
        with open(filename, 'r') as f:
            for line in f:
                if line.strip():
                    processed_count += 1
                    yield f"Processed: {line.strip()}"
        
        return processed_count

if __name__ == "__main__":
    # Example usage
    print("=== Simple Generator ===")
    for square in simple_generator(5):
        print(f"Square: {square}")
    
    print("\n=== Fibonacci Generator ===")
    for fib in fibonacci_generator(20):
        print(f"Fibonacci: {fib}")
    
    print("\n=== Custom Iterator ===")
    seq = NumberSequence(0, 10, 2)
    for num in seq:
        print(f"Number: {num}")
    
    print("\n=== Tree Iterator ===")
    # Create a simple tree
    root = TreeNode(1)
    root.left = TreeNode(2)
    root.right = TreeNode(3)
    root.left.left = TreeNode(4)
    root.left.right = TreeNode(5)
    
    for value in TreeIterator(root):
        print(f"Tree value: {value}")
    
    print("\n=== Generator Expressions ===")
    squares, evens = generator_expression_example()
    print(f"Squares: {squares}")
    print(f"Evens: {evens}")
    
    print("\n=== Nested Generators ===")
    nested_result = nested_generators()
    print(f"Nested: {nested_result}")
    
    print("\n=== Generator with Send ===")
    send_result = generator_with_send()
    print(f"Send result: {send_result}")
    
    print("\n=== Generator with Throw ===")
    throw_result = generator_with_throw()
    print(f"Throw result: {throw_result}")
    
    print("\n=== Batch Processing ===")
    data = list(range(1, 11))
    for batch_sum in batch_processor(data, 3):
        print(f"Batch sum: {batch_sum}")
    
    print("\n=== Memory Efficient Processing ===")
    count = memory_efficient_processing()
    print(f"Processed {count} lines")
