"""
BOUNDS True Negative #2: Dict.get() with default

Expected: SAFE
Safety mechanism: dict.get() returns default instead of raising KeyError
Semantic basis: No KeyError path exists
"""

def safe_dict_access():
    data = {'name': 'Bob', 'age': 25}
    # SAFE: dict.get() with default never raises KeyError
    value = data.get('missing_key', 'default_value')
    return value

if __name__ == "__main__":
    result = safe_dict_access()
    print(f"Result: {result}")
