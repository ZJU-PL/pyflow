"""
Paper #20 exercise: Compositional/Assume-Guarantee.

Multiple cooperating functions — the analyzer decomposes
them into components and uses assume-guarantee reasoning.

Target papers: #20 (Assume-Guarantee Compositional Reasoning)
Expected: SAFE
"""


def producer(n):
    """Produce values from 0 to n-1."""
    result = []
    i = 0
    while i < n:
        result.append(i)
        i += 1
    return result


def consumer(items):
    """Consume a list of non-negative integers."""
    total = 0
    j = 0
    while j < len(items):
        total += items[j]
        j += 1
    return total


def pipeline(n):
    """End-to-end pipeline: produce then consume."""
    data = producer(n)
    return consumer(data)
