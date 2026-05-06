"""
TYPE_CONFUSION True Negative #1: isinstance check before use

Expected: SAFE
Reason: Type is checked with isinstance before type-specific operations
"""

def process_value(value):
    """Properly checks type before using type-specific methods"""
    if isinstance(value, dict):
        return value.get('key', 'default')
    elif isinstance(value, list):
        return value[0] if value else None
    elif isinstance(value, str):
        return value.upper()
    else:
        return str(value)

def main():
    # All paths type-safe due to isinstance guards
    result1 = process_value({'key': 'value'})
    result2 = process_value([1, 2, 3])
    result3 = process_value("hello")
    result4 = process_value(42)
    print(result1, result2, result3, result4)

if __name__ == "__main__":
    main()
