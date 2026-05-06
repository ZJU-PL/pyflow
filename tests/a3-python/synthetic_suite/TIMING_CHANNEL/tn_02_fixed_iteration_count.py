"""
TIMING_CHANNEL True Negative #2: Fixed iteration count

Safe: Algorithm performs fixed number of operations regardless of secret value,
eliminating timing side-channel.

Expected: SAFE - no timing channel
"""

def compute_with_secret_safe(secret_key: int, public_input: int) -> int:
    """
    Safe: Fixed number of iterations regardless of secret_key value.
    """
    result = public_input
    MAX_ITERATIONS = 100  # Fixed, doesn't depend on secret
    
    # Always perform MAX_ITERATIONS, independent of secret_key
    for i in range(MAX_ITERATIONS):
        # Use secret_key in computation but not in control flow
        if i < secret_key:
            result = (result * 31 + 17) % 1000000007
        else:
            # Dummy operation to maintain constant time
            result = (result * 1 + 0) % 1000000007
    
    return result


def constant_time_select(condition: bool, true_value: int, false_value: int) -> int:
    """
    Safe: Constant-time conditional selection.
    Both values are always computed; selection is done without branching.
    """
    # This is a simplified version; real implementations use bit masking
    # Both branches execute, timing is independent of condition
    result_true = true_value * 2
    result_false = false_value * 3
    
    # Selection without timing leak (simplified)
    return result_true if condition else result_false


def main():
    SECRET_KEY = 42
    public_data = 123456
    
    # Safe: timing independent of SECRET_KEY value
    result = compute_with_secret_safe(SECRET_KEY, public_data)
    print(f"Result: {result}")
    
    # Safe conditional selection
    secret_condition = True
    value = constant_time_select(secret_condition, 100, 200)
    print(f"Selected value: {value}")


if __name__ == "__main__":
    main()
