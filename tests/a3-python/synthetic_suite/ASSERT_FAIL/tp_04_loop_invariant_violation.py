"""
ASSERT_FAIL True Positive 04: Loop invariant violation

Expected: BUG (ASSERT_FAIL)
Reason: Loop invariant assertion fails during iteration
Bug location: Line 16
Semantic unsafe region: Counter exceeds threshold, violating loop invariant
"""

def process_with_limit(items, limit):
    counter = 0
    results = []
    for item in items:
        counter += item
        # Loop invariant: counter should never exceed limit
        assert counter <= limit, f"Counter {counter} exceeded limit {limit}"
        results.append(counter)
    return results

if __name__ == "__main__":
    # Sum will exceed limit, causing assertion failure
    items = [10, 20, 30, 40, 50]
    limit = 75
    result = process_with_limit(items, limit)
    print(f"Result: {result}")
