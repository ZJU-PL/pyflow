"""
TYPE_CONFUSION True Negative #4: Union type with proper narrowing

Expected: SAFE
Reason: All type variants in union are handled explicitly before operations
"""

from typing import Union

def process_data(data: Union[str, list, dict]) -> str:
    """Properly narrows union type before operations"""
    if isinstance(data, str):
        # Handle string case
        return data.upper()
    elif isinstance(data, list):
        # Handle list case
        return f"List with {len(data)} items"
    elif isinstance(data, dict):
        # Handle dict case
        return f"Dict with keys: {', '.join(data.keys())}"
    else:
        # Defensive fallback
        return str(data)

def main():
    # All type variants handled safely
    result1 = process_data("hello")
    result2 = process_data([1, 2, 3])
    result3 = process_data({'a': 1, 'b': 2})
    print(result1, result2, result3)

if __name__ == "__main__":
    main()
