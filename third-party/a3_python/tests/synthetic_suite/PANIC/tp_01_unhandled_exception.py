"""
PANIC true positive #1: Unhandled exception propagation

Ground truth: BUG (PANIC)
Reason: ValueError raised without any exception handler to catch it.
        The exception propagates to the top level causing program termination.

Expected analyzer behavior:
- Should detect that ValueError can be raised at line with int(user_input)
- Should verify no exception handler exists in call stack
- Should report PANIC: unhandled exception can terminate program
"""

def parse_config(user_input: str) -> int:
    """Parse user input to integer - no exception handling."""
    value = int(user_input)  # Can raise ValueError
    return value * 2

def main():
    result = parse_config("not_a_number")
    print(f"Result: {result}")

if __name__ == "__main__":
    main()
