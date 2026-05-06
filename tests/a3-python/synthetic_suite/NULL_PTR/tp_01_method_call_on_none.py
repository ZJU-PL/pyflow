"""
NULL_PTR True Positive #1: Method call on None

Ground truth: BUG
Bug type: NULL_PTR
Reason: Calling .upper() on None causes AttributeError

Semantic model: Value is None (NULL_PTR), method call dereferences None.
"""

def get_value():
    return None

def main():
    result = get_value()
    # BUG: result is None, calling .upper() will raise AttributeError
    output = result.upper()
    print(output)

if __name__ == "__main__":
    main()
