"""
INTEGER_OVERFLOW True Positive #2: array module overflow
EXPECTED: BUG
REASON: array('b') stores signed bytes (-128 to 127), value wraps
"""
import array

def overflow_signed_byte_array():
    arr = array.array('b', [100])
    # Adding 50 to 100 should give 150, but 'b' wraps to -106
    arr[0] = arr[0] + 50
    # The semantic intent (value >= 150) is violated by wrapping
    if arr[0] < 0:
        raise ValueError(f"Overflow detected: expected 150, got {arr[0]}")
    return arr[0]

if __name__ == "__main__":
    try:
        result = overflow_signed_byte_array()
        print(f"Result: {result}")
    except ValueError as e:
        print(f"Error: {e}")
