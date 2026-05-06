"""
PANIC true positive #2: Explicit raise without enclosing try

Ground truth: BUG (PANIC)
Reason: Unconditional raise statement with no exception handler.
        The RuntimeError is raised and propagates uncaught.

Expected analyzer behavior:
- Should detect unconditional raise statement
- Should verify no try-except block in scope
- Should report PANIC: uncaught exception will terminate program
"""

def validate_input(value: int) -> None:
    """Validate input - always raises on invalid input."""
    if value < 0:
        raise RuntimeError("Negative values not allowed")
    # Even positive values go to else
    raise RuntimeError("Validation failed")

def process(value: int) -> int:
    validate_input(value)
    return value * 2

def main():
    result = process(5)
    print(f"Result: {result}")

if __name__ == "__main__":
    main()
