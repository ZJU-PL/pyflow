"""
INTEGER_OVERFLOW True Positive #4: ctypes multiplication overflow
EXPECTED: BUG
REASON: c_uint8 multiplication overflows and wraps
"""
import ctypes

def overflow_multiplication():
    # c_uint8: 0 to 255
    a = ctypes.c_uint8(200)
    b = ctypes.c_uint8(2)
    # 200 * 2 = 400, which overflows to 144 in uint8
    result = ctypes.c_uint8(a.value * b.value)
    # Expected 400 but got wrapped value
    if result.value < 300:
        raise OverflowError(f"Multiplication overflow: expected 400, got {result.value}")
    return result.value

if __name__ == "__main__":
    try:
        result = overflow_multiplication()
        print(f"Result: {result}")
    except OverflowError as e:
        print(f"Error: {e}")
