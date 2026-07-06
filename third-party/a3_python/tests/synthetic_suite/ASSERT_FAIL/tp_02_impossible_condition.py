"""
ASSERT_FAIL True Positive 02: Assert with impossible condition

Expected: BUG (ASSERT_FAIL)
Reason: Assertion checks a condition that is always False (x > x is impossible)
Bug location: Line 11
Semantic unsafe region: AssertionError for condition that can never be satisfied
"""

def check_impossible(x):
    # This condition is always False
    assert x > x, f"Impossible: {x} > {x}"
    return x

if __name__ == "__main__":
    result = check_impossible(10)
    print(f"Result: {result}")
