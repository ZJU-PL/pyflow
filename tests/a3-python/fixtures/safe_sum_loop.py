"""
Test program: safe bounded loop with clear invariant.

This program should be provable SAFE with a ranking function
for termination and bounds check ensuring no out-of-bounds access.

Invariants:
- i starts at 0 and increases by 1 each iteration
- Loop terminates when i >= n (always with finite n)
- No divisions, no assertions, no array accesses
- Ranking function: R(σ) = n - i (always decreases, always >= 0 in loop)
"""

def safe_sum_to_n(n):
    """
    Compute sum of integers from 0 to n-1.
    Safe: bounded loop, no unsafe operations.
    
    Args:
        n: Upper bound (assume n >= 0)
    
    Returns:
        Sum of integers 0 + 1 + ... + (n-1)
    """
    total = 0
    i = 0
    # Loop invariant: 0 <= i <= n
    # Ranking function: R = n - i, decreases each iteration
    while i < n:
        total = total + i
        i = i + 1
    return total

# Call with concrete safe value
result = safe_sum_to_n(10)
