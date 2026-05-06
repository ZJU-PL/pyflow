"""
NULL_PTR True Positive #3: Subscript operation on None

Ground truth: BUG
Bug type: NULL_PTR
Reason: Subscripting None raises TypeError

Semantic model: Value is None, subscript operation requires indexable object.
"""

def parse_data(flag):
    if flag:
        return [1, 2, 3]
    return None

def main():
    # BUG: parse_data returns None when flag=False
    data = parse_data(False)
    # Subscripting None raises TypeError
    first = data[0]
    print(first)

if __name__ == "__main__":
    main()
