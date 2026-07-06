"""
UNINIT_MEMORY True Negative #5: Loop with safe default before iteration

Bug type: UNINIT_MEMORY
Expected result: SAFE
Reason: Variable is initialized with a default value before the loop,
        ensuring it has a value even if the loop doesn't iterate or
        doesn't find matching elements.

Semantic: Def-before-use guaranteed by sequencing: assignment precedes
all paths through loop and post-loop use.
"""

def find_last_even_safe(numbers: list[int]) -> int:
    # Initialize with default value before loop
    last_even = None
    
    for num in numbers:
        if num % 2 == 0:
            last_even = num
    
    # SAFE: last_even is always assigned (to None initially)
    return last_even if last_even is not None else -1

def accumulate_sum(values: list[int]) -> int:
    # Initialize accumulator before loop
    total = 0
    
    for value in values:
        total += value
    
    # SAFE: total is initialized before loop, updated in loop
    return total

if __name__ == "__main__":
    result1 = find_last_even_safe([1, 3, 5])
    result2 = find_last_even_safe([1, 2, 4, 5])
    result3 = accumulate_sum([1, 2, 3, 4])
    result4 = accumulate_sum([])  # Empty list
    print(f"Results: {result1}, {result2}, {result3}, {result4}")
