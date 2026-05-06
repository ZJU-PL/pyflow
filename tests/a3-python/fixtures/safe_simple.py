"""
Test program: simple safe computation.

This program does a simple bounded computation that never
reaches any unsafe region. Should be provable SAFE with
a barrier certificate.
"""

def safe_computation():
    """
    Safe function: bounded computation with no divisions by zero,
    no assertions, no array accesses.
    """
    x = 5
    y = 10
    z = x + y
    return z

# Call the function
result = safe_computation()
