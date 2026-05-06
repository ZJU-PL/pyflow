"""
INTEGER_OVERFLOW True Negative #4: Checked ctypes operations
EXPECTED: SAFE
REASON: Values are validated before assignment to fixed-width types
"""
import ctypes

def safe_checked_c_int8(value: int) -> ctypes.c_int8:
    """Safely create c_int8 with range check."""
    if not (-128 <= value <= 127):
        raise ValueError(f"Value {value} out of range for c_int8")
    return ctypes.c_int8(value)

def safe_c_int8_addition(a: int, b: int) -> int:
    """Add two values safely for c_int8."""
    result = a + b
    if not (-128 <= result <= 127):
        raise ValueError(f"Result {result} would overflow c_int8")
    c = ctypes.c_int8(result)
    assert c.value == result
    return c.value

if __name__ == "__main__":
    x = safe_checked_c_int8(50)
    print(f"Safe c_int8: {x.value}")
    
    y = safe_c_int8_addition(30, 40)
    print(f"Safe addition: {y}")
    
    try:
        safe_c_int8_addition(100, 50)  # Would overflow
    except ValueError as e:
        print(f"Caught overflow: {e}")
