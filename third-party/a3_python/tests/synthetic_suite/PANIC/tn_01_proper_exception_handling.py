"""
PANIC true negative #1: Proper exception handling

Ground truth: SAFE
Reason: All potential exceptions are caught and handled gracefully.
        The program cannot terminate due to unhandled exceptions.

Expected analyzer behavior:
- Should verify ValueError is caught by except block
- Should verify all code paths either succeed or handle exceptions
- Should report SAFE: no unhandled exception path exists
"""

def parse_config(user_input: str) -> int:
    """Parse user input to integer with exception handling."""
    try:
        value = int(user_input)
        return value * 2
    except ValueError as e:
        print(f"Invalid input: {e}")
        return 0  # Safe default

def main():
    result = parse_config("not_a_number")
    print(f"Result: {result}")

if __name__ == "__main__":
    main()
