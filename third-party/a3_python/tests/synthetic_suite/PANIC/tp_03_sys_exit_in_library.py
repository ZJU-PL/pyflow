"""
PANIC true positive #3: sys.exit() called in library code

Ground truth: BUG (PANIC)
Reason: Library function calls sys.exit() which terminates the entire program
        abruptly without allowing the caller to handle the error condition.

Expected analyzer behavior:
- Should detect sys.exit() call in library function (non-main context)
- Should recognize this violates "library functions should not terminate program" contract
- Should report PANIC: library code causes program termination
"""

import sys

def library_function(config_file: str) -> dict:
    """Library function that incorrectly calls sys.exit()."""
    try:
        with open(config_file, 'r') as f:
            return {}
    except FileNotFoundError:
        # Library code should raise exception, not exit
        sys.exit(1)  # BUG: terminates entire program

def main():
    config = library_function("nonexistent.conf")
    print(f"Config: {config}")

if __name__ == "__main__":
    main()
