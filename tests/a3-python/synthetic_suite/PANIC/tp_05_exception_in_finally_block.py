"""
PANIC true positive #5: Exception raised in finally block

Ground truth: BUG (PANIC)
Reason: Exception raised in finally block masks the original exception
        and propagates uncaught, causing program termination.

Expected analyzer behavior:
- Should detect exception can be raised in finally block
- Should recognize this masks any pending exception from try block
- Should verify no outer exception handler exists
- Should report PANIC: finally-block exception terminates program
"""

def cleanup_and_process(filename: str) -> str:
    """Process file with cleanup that can fail."""
    try:
        with open(filename, 'r') as f:
            data = f.read()
        return data
    finally:
        # Cleanup code that raises - masks any exception from try block
        result = 1 / 0  # ZeroDivisionError uncaught

def main():
    content = cleanup_and_process("data.txt")
    print(f"Content: {content}")

if __name__ == "__main__":
    main()
