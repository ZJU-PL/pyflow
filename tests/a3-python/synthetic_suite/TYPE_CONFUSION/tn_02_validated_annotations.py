"""
TYPE_CONFUSION True Negative #2: Proper type annotations honored with validation

Expected: SAFE
Reason: Function validates input type at runtime, matching annotation contract
"""

def calculate_total(base_price: float, tax_rate: float) -> float:
    """Type-checked calculation with explicit validation"""
    # Runtime type validation
    if not isinstance(base_price, (int, float)):
        raise TypeError(f"base_price must be numeric, got {type(base_price)}")
    if not isinstance(tax_rate, (int, float)):
        raise TypeError(f"tax_rate must be numeric, got {type(tax_rate)}")
    
    return base_price * (1 + tax_rate)

def main():
    # Correct types provided
    total = calculate_total(100.0, 0.08)
    print(f"Total: {total}")

if __name__ == "__main__":
    main()
