#!/usr/bin/env python3
"""
Recursive Functions Example for PyFlow

This example demonstrates recursive function calls and algorithms
that can be analyzed by PyFlow's inter-procedural analysis (IPA).

Usage:
    pyflow optimize recursive_functions.py --analysis ipa
    pyflow callgraph recursive_functions.py
"""

def factorial(n):
    """Calculate factorial using recursion."""
    if n <= 1:
        return 1
    else:
        return n * factorial(n - 1)

def fibonacci(n):
    """Calculate nth Fibonacci number using recursion."""
    if n <= 1:
        return n
    else:
        return fibonacci(n - 1) + fibonacci(n - 2)

def binary_search(arr, target, left=0, right=None):
    """Binary search using recursion."""
    if right is None:
        right = len(arr) - 1
    
    if left > right:
        return -1
    
    mid = (left + right) // 2
    
    if arr[mid] == target:
        return mid
    elif arr[mid] > target:
        return binary_search(arr, target, left, mid - 1)
    else:
        return binary_search(arr, target, mid + 1, right)

def tree_traversal(node, result=None):
    """In-order tree traversal using recursion."""
    if result is None:
        result = []
    
    if node is not None:
        tree_traversal(node.left, result)
        result.append(node.value)
        tree_traversal(node.right, result)
    
    return result

def count_digits(n):
    """Count the number of digits in a number using recursion."""
    if n < 10:
        return 1
    else:
        return 1 + count_digits(n // 10)

def power(base, exponent):
    """Calculate base^exponent using recursion."""
    if exponent == 0:
        return 1
    elif exponent < 0:
        return 1 / power(base, -exponent)
    else:
        return base * power(base, exponent - 1)

def gcd(a, b):
    """Calculate greatest common divisor using recursion."""
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def tower_of_hanoi(n, source, destination, auxiliary):
    """Solve Tower of Hanoi puzzle using recursion."""
    if n == 1:
        print(f"Move disk 1 from {source} to {destination}")
        return
    
    tower_of_hanoi(n - 1, source, auxiliary, destination)
    print(f"Move disk {n} from {source} to {destination}")
    tower_of_hanoi(n - 1, auxiliary, destination, source)

# Simple tree node class for demonstration
class TreeNode:
    def __init__(self, value, left=None, right=None):
        self.value = value
        self.left = left
        self.right = right

if __name__ == "__main__":
    # Example usage
    print(f"Factorial of 5: {factorial(5)}")
    print(f"Fibonacci(8): {fibonacci(8)}")
    
    numbers = [1, 3, 5, 7, 9, 11, 13, 15]
    target = 7
    index = binary_search(numbers, target)
    print(f"Binary search for {target} in {numbers}: index {index}")
    
    print(f"Number of digits in 12345: {count_digits(12345)}")
    print(f"2^8 = {power(2, 8)}")
    print(f"GCD of 48 and 18: {gcd(48, 18)}")
    
    # Create a simple binary tree
    root = TreeNode(4)
    root.left = TreeNode(2)
    root.right = TreeNode(6)
    root.left.left = TreeNode(1)
    root.left.right = TreeNode(3)
    root.right.left = TreeNode(5)
    root.right.right = TreeNode(7)
    
    traversal = tree_traversal(root)
    print(f"Tree traversal: {traversal}")
    
    print("\nTower of Hanoi (3 disks):")
    tower_of_hanoi(3, 'A', 'C', 'B')
