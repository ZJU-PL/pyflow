"""
BOUNDS True Negative #5: try-except KeyError handling

Expected: SAFE
Safety mechanism: KeyError caught and handled
Semantic basis: Exception handler catches potential BOUNDS violation
"""

def safe_dict_with_exception_handling():
    data = {'a': 1, 'b': 2}
    try:
        # Potential KeyError, but caught
        value = data['c']
        return value
    except KeyError:
        # SAFE: Exception is handled
        return 'key_not_found'

if __name__ == "__main__":
    result = safe_dict_with_exception_handling()
    print(f"Result: {result}")
