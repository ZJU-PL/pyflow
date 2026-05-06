"""
ASSERT_FAIL True Negative 05: Loop invariant maintained

Expected: SAFE
Reason: Loop invariant is always satisfied throughout execution
Semantic: Assertion condition is inductive invariant that holds at all iterations
"""

def safe_accumulate(items, limit):
    counter = 0
    results = []
    for item in items:
        # Only add if it won't exceed limit
        if counter + item <= limit:
            counter += item
            results.append(counter)
        # Loop invariant: counter never exceeds limit
        assert counter <= limit, f"Counter {counter} exceeded limit {limit}"
    return results

if __name__ == "__main__":
    # Items designed to respect the limit
    items = [10, 20, 30, 40, 50]
    limit = 100
    result = safe_accumulate(items, limit)
    print(f"Result: {result}")
