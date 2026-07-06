"""
BOUNDS True Positive #3: Dictionary key access on missing key

Expected: BUG (KeyError)
Bug location: Line accessing data['missing_key']
Semantic basis: BOUNDS violation - key not in dict domain
"""

def dict_key_missing():
    data = {'name': 'Alice', 'age': 30}
    # BUG: 'missing_key' is not in the dictionary
    value = data['missing_key']
    return value

if __name__ == "__main__":
    result = dict_key_missing()
    print(f"Result: {result}")
