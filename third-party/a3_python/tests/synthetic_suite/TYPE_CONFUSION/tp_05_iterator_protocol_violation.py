"""
TYPE_CONFUSION True Positive #5: Iterator protocol violation

Expected: BUG (TYPE_CONFUSION)
Reason: Code expects iterable but receives non-iterable integer, causing TypeError
"""

def sum_items(items):
    """Expects an iterable collection"""
    total = 0
    # Bug: no check that items is actually iterable
    for item in items:  # TypeError: 'int' object is not iterable
        total += item
    return total

def main():
    # Pass integer instead of list/tuple/iterable
    result = sum_items(42)
    print(f"Sum: {result}")

if __name__ == "__main__":
    main()
