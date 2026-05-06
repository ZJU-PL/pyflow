"""
INTEGER_OVERFLOW True Negative #1: Pure Python arithmetic (no overflow)
EXPECTED: SAFE
REASON: Python integers have arbitrary precision, never overflow
"""

def safe_large_arithmetic():
    # Python can handle arbitrarily large integers
    large = 10 ** 100
    result = large * large  # 10^200, perfectly fine
    assert result == 10 ** 200
    return result

def safe_deep_multiplication():
    x = 1
    for i in range(1000):
        x = x * 2  # 2^1000 is huge but safe in Python
    assert x == 2 ** 1000
    return x

if __name__ == "__main__":
    r1 = safe_large_arithmetic()
    r2 = safe_deep_multiplication()
    print(f"Large arithmetic: {len(str(r1))} digits")
    print(f"Deep multiplication: {len(str(r2))} digits")
