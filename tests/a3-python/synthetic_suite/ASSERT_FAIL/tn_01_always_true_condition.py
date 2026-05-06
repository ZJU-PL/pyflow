"""
ASSERT_FAIL True Negative 01: Assert with true condition

Expected: SAFE
Reason: Assertion condition is always True, will never fail
Semantic: No path reaches AssertionError
"""

def always_succeeds():
    assert True, "This assertion always passes"
    return 42

if __name__ == "__main__":
    result = always_succeeds()
    print(f"Result: {result}")
