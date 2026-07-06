"""
ASSERT_FAIL True Positive 01: Unconditional assert False

Expected: BUG (ASSERT_FAIL)
Reason: assert False statement will always fail and raise AssertionError with no handler
Bug location: Line 10
Semantic unsafe region: AssertionError propagates to top-level (unhandled)
"""

def always_fails():
    assert False, "This assertion always fails"
    return 42

if __name__ == "__main__":
    result = always_fails()
    print(f"Result: {result}")
