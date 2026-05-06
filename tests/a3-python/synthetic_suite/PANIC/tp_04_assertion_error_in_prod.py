"""
PANIC true positive #4: AssertionError propagating in production code

Ground truth: BUG (PANIC)
Reason: assert statement can raise AssertionError in production (not just debug).
        The assertion failure is not caught, causing program crash.

Expected analyzer behavior:
- Should detect assert statement that can fail (condition not proven true)
- Should verify no exception handler for AssertionError
- Should report PANIC: assertion failure can terminate program
"""

def calculate_discount(price: float, discount_percent: float) -> float:
    """Calculate discounted price with assertion validation."""
    assert discount_percent <= 100, "Discount cannot exceed 100%"
    discounted = price * (1 - discount_percent / 100)
    assert discounted >= 0, "Discounted price cannot be negative"
    return discounted

def main():
    # This call will fail the assertion
    price = calculate_discount(100.0, 150.0)
    print(f"Final price: {price}")

if __name__ == "__main__":
    main()
