"""
INTEGER_OVERFLOW True Positive #5: Integer underflow (signed)
EXPECTED: BUG
REASON: c_int8 underflows when value goes below -128
"""
import ctypes

def underflow_subtraction():
    # c_int8: -128 to 127
    x = ctypes.c_int8(-100)
    x.value = x.value - 50  # -150 underflows to 106
    # Semantic expectation violated
    assert x.value == -150  # Will fail: x.value is actually 106
    return x.value

if __name__ == "__main__":
    result = underflow_subtraction()
    print(f"Result: {result}")
