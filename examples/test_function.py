#!/usr/bin/env python3
"""
Test function for demonstrating PyFlow CLI options.
"""

def fibonacci(n):
    """Calculate the nth Fibonacci number."""
    if n <= 1:
        return n
    else:
        return fibonacci(n - 1) + fibonacci(n - 2)


def factorial(n):
    """Calculate the factorial of n."""
    result = 1
    for i in range(1, n + 1):
        result = result * i
    return result


def quicksort(arr):
    """Sort an array using quicksort algorithm."""
    if len(arr) <= 1:
        return arr
    
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    
    return quicksort(left) + middle + quicksort(right)


def binary_search(arr, target):
    """Binary search implementation."""
    left, right = 0, len(arr) - 1
    
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1


if __name__ == "__main__":
    # Test the functions
    print("Fibonacci(10) =", fibonacci(10))
    print("Factorial(5) =", factorial(5))
    print("Quicksort([3, 1, 4, 1, 5, 9]) =", quicksort([3, 1, 4, 1, 5, 9]))
    print("Binary search for 4 in [1, 3, 4, 6, 8] =", binary_search([1, 3, 4, 6, 8], 4))
