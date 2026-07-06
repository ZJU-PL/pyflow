"""
INTEGER_OVERFLOW True Positive #1: ctypes integer overflow
EXPECTED: BUG
REASON: c_int8 overflows when assigned value > 127
"""
import ctypes

def overflow_c_int8():
    # c_int8 can only hold values from -128 to 127
    x = ctypes.c_int8(100)
    x.value = x.value + 50  # 150 overflows to -106
    # This is undefined behavior in the sense that the semantic value
    # changed unexpectedly
    assert x.value == 150  # Will fail: x.value is actually -106
    return x.value

if __name__ == "__main__":
    result = overflow_c_int8()
    print(f"Result: {result}")
