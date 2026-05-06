"""
INTEGER_OVERFLOW True Negative #3: Operations on small constants
EXPECTED: SAFE
REASON: All values are small enough to be safe even in fixed-width contexts
"""

def safe_small_operations():
    # All operations use values that would be safe even in int32
    a = 10
    b = 20
    c = a + b
    d = c * 2
    e = d - 5
    
    assert c == 30
    assert d == 60
    assert e == 55
    
    return e

def safe_small_loop():
    total = 0
    for i in range(100):
        total += i
    assert total == 4950  # Well within any reasonable bounds
    return total

if __name__ == "__main__":
    r1 = safe_small_operations()
    r2 = safe_small_loop()
    print(f"Small operations: {r1}")
    print(f"Small loop: {r2}")
