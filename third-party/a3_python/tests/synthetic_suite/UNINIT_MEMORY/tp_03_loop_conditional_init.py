"""
UNINIT_MEMORY True Positive #3: Loop with conditional initialization

Bug type: UNINIT_MEMORY
Expected result: BUG
Reason: Variable 'last_even' is only assigned inside the loop if an even
        number is found. If the list is empty or contains only odd numbers,
        'last_even' is never assigned before use.

Semantic: Use-before-def via empty-iteration or filtered-iteration path.
"""

def find_last_even(numbers: list[int]) -> int:
    for num in numbers:
        if num % 2 == 0:
            last_even = num
    
    # BUG: if no even numbers exist in the list, 'last_even' is uninitialized
    return last_even  # UnboundLocalError when all odd or empty list

if __name__ == "__main__":
    # Trigger the bug with an all-odd list
    result = find_last_even([1, 3, 5, 7])
    print(result)
