"""
TYPE_CONFUSION True Positive #4: Numeric string confusion in arithmetic

Expected: BUG (TYPE_CONFUSION)
Reason: String passed where number expected, causing TypeError in arithmetic operation
"""

def calculate_total(base_price, tax_rate):
    """Expects numeric types for calculation"""
    # Bug: no type validation before arithmetic
    total = base_price * (1 + tax_rate)  # TypeError if either is string
    return total

def main():
    # Pass string instead of float for tax_rate
    total = calculate_total(100, "0.08")  # String * causes TypeError
    print(f"Total: {total}")

if __name__ == "__main__":
    main()
