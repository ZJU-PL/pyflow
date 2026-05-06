"""
PANIC true negative #2: Graceful degradation pattern

Ground truth: SAFE
Reason: All exceptions are caught at top level with graceful fallback.
        The program continues execution with degraded functionality.

Expected analyzer behavior:
- Should verify top-level try-except catches all exceptions
- Should verify program continues after exception (doesn't re-raise)
- Should report SAFE: all exceptions handled gracefully
"""

def risky_operation(value: int) -> int:
    """Operation that might fail."""
    if value < 0:
        raise ValueError("Negative value")
    return 100 // value  # Can raise ZeroDivisionError

def process_with_fallback(value: int) -> int:
    """Process with graceful degradation."""
    try:
        return risky_operation(value)
    except (ValueError, ZeroDivisionError) as e:
        print(f"Operation failed: {e}, using fallback")
        return -1  # Sentinel value indicating fallback

def main():
    result1 = process_with_fallback(0)  # Would ZeroDivisionError, but handled
    result2 = process_with_fallback(-5)  # Would ValueError, but handled
    result3 = process_with_fallback(10)  # Success
    print(f"Results: {result1}, {result2}, {result3}")

if __name__ == "__main__":
    main()
