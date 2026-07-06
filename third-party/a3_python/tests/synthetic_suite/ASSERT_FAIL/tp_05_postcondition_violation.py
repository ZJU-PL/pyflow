"""
ASSERT_FAIL True Positive 05: Postcondition assertion failure

Expected: BUG (ASSERT_FAIL)
Reason: Function returns value that violates postcondition assertion
Bug location: Line 15
Semantic unsafe region: Result does not satisfy postcondition constraint
"""

def compute_positive_value(x):
    # Buggy computation: can return negative value
    result = x - 100
    
    # Postcondition: result must be positive
    assert result > 0, f"Postcondition violated: {result} is not positive"
    return result

if __name__ == "__main__":
    # Input too small, postcondition will fail
    value = compute_positive_value(50)
    print(f"Value: {value}")
