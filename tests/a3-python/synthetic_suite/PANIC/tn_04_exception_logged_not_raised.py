"""
PANIC true negative #4: Exception logged but not raised

Ground truth: SAFE
Reason: Potential exceptions are caught, logged, and converted to return values.
        No exception propagates to caller.

Expected analyzer behavior:
- Should verify all exceptions caught in try-except
- Should verify no re-raise or new exception in exception handlers
- Should report SAFE: exceptions cannot escape this code
"""

import sys

def safe_divide(a: int, b: int) -> tuple[bool, float]:
    """Division with exception converted to return value."""
    try:
        result = a / b
        return (True, result)
    except ZeroDivisionError as e:
        print(f"Error: {e}", file=sys.stderr)
        return (False, 0.0)  # Error indication without exception

def safe_parse(value: str) -> tuple[bool, int]:
    """Parse with exception converted to return value."""
    try:
        num = int(value)
        return (True, num)
    except ValueError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return (False, 0)

def main():
    success1, result1 = safe_divide(10, 0)
    success2, result2 = safe_parse("not_a_number")
    
    if success1:
        print(f"Division result: {result1}")
    else:
        print("Division failed")
    
    if success2:
        print(f"Parse result: {result2}")
    else:
        print("Parse failed")

if __name__ == "__main__":
    main()
