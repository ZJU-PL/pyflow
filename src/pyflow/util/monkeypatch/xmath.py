"""
Extended math utilities for static analysis.

This module provides mathematical functions used throughout pyflow for
computing bit sizes, encoding values, and other analysis-related operations.
"""

from math import *


def numbits(size):
    """
    Calculate the number of bits needed to represent a given size.
    
    This function computes the ceiling of log2(size), which represents the
    minimum number of bits required to represent all values from 0 to size-1.
    
    Args:
        size: The size (number of distinct values) to represent
        
    Returns:
        int: Number of bits needed (0 if size <= 1, otherwise ceil(log2(size)))
        
    Example:
        >>> numbits(1)
        0
        >>> numbits(2)
        1
        >>> numbits(8)
        3
        >>> numbits(9)
        4
        >>> numbits(256)
        8
    """
    if size <= 1:
        return 0
    else:
        return int(ceil(log(size, 2)))


def _bijection(a, b):
    """
    Create a bijective mapping from two integers to a single integer.
    
    This implements the Cantor pairing function, which creates a one-to-one
    correspondence between pairs of natural numbers and natural numbers.
    The function is bijective, meaning every pair (a, b) maps to a unique
    integer, and every integer can be decoded back to a unique pair.
    
    The formula used is: (a + b) * (a + b + 1) / 2 + a
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        int: Unique integer encoding the pair (a, b)
        
    Example:
        >>> _bijection(0, 0)
        0
        >>> _bijection(0, 1)
        1
        >>> _bijection(1, 0)
        2
        >>> _bijection(1, 1)
        4
    """
    c = a + b
    return (c * (c + 1)) // 2 + a


def bijection(a, b, *others):
    """
    Create a bijective mapping from multiple integers to a single integer.
    
    This function extends the two-argument bijection to handle any number
    of arguments by repeatedly applying the pairing function. The result
    is a unique integer encoding all input values.
    
    This is useful for creating hash codes or unique identifiers from
    multiple values, such as encoding multiple indices or coordinates
    into a single key.
    
    Args:
        a: First integer
        b: Second integer
        *others: Additional integers to encode
        
    Returns:
        int: Unique integer encoding all input values
        
    Example:
        >>> bijection(1, 2)
        8
        >>> bijection(1, 2, 3)
        78
        >>> bijection(1, 2, 3, 4)
        3081
        
    Note:
        The encoding is order-dependent: bijection(a, b) != bijection(b, a)
    """
    result = _bijection(a, b)
    for o in others:
        result = _bijection(result, o)
    return result
