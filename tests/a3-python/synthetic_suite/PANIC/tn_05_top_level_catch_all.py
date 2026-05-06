"""
PANIC true negative #5: Top-level catch-all exception handler

Ground truth: SAFE
Reason: Top-level try-except catches all exceptions including base Exception.
        No exception can terminate the program.

Expected analyzer behavior:
- Should verify top-level except Exception (or bare except) catches all
- Should verify the handler doesn't re-raise
- Should report SAFE: no exception can escape to cause program termination
"""

def potentially_failing_operation(value: int) -> int:
    """Operation with multiple failure modes."""
    if value < 0:
        raise ValueError("Negative value")
    if value == 0:
        return 1 // value  # ZeroDivisionError
    if value > 100:
        raise RuntimeError("Value too large")
    return value * 2

def main():
    """Main function with catch-all exception handler."""
    test_values = [-1, 0, 50, 150]
    
    for value in test_values:
        try:
            result = potentially_failing_operation(value)
            print(f"Success for {value}: {result}")
        except Exception as e:
            # Catch-all handler ensures no exception terminates program
            print(f"Failed for {value}: {type(e).__name__}: {e}")
    
    print("Program completed successfully")

if __name__ == "__main__":
    main()
