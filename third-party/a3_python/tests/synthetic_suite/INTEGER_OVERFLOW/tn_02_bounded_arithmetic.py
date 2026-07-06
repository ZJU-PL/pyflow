"""
INTEGER_OVERFLOW True Negative #2: Bounded arithmetic with range checks
EXPECTED: SAFE
REASON: Values are checked to stay within bounds before operations
"""

def safe_bounded_add(a: int, b: int, max_val: int = 1000) -> int:
    """Add two integers with overflow check."""
    if a > max_val - b:
        raise ValueError(f"Would overflow max {max_val}")
    result = a + b
    assert result <= max_val
    return result

def safe_bounded_multiply(a: int, b: int, max_val: int = 1000) -> int:
    """Multiply with overflow check."""
    if b != 0 and a > max_val // b:
        raise ValueError(f"Would overflow max {max_val}")
    result = a * b
    assert result <= max_val
    return result

if __name__ == "__main__":
    r1 = safe_bounded_add(100, 200)
    r2 = safe_bounded_multiply(10, 20)
    print(f"Bounded add: {r1}")
    print(f"Bounded multiply: {r2}")
    
    try:
        safe_bounded_add(900, 200)  # Would overflow
    except ValueError as e:
        print(f"Caught overflow: {e}")
