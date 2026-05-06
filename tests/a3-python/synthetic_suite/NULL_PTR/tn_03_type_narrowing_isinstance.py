"""
NULL_PTR True Negative #3: Type narrowing via isinstance

Ground truth: SAFE
Bug type: NULL_PTR
Reason: isinstance check establishes type is not None

Semantic model: Type guard ensures value is specific type (not None) at dereference.
"""

def parse_data(flag):
    if flag:
        return [1, 2, 3]
    return None

def main():
    data = parse_data(False)
    # SAFE: isinstance check both validates type and excludes None
    if isinstance(data, list):
        first = data[0]
        print(first)
    else:
        print("No data")

if __name__ == "__main__":
    main()
