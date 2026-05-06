"""
NULL_PTR True Positive #4: Iteration over None

Ground truth: BUG
Bug type: NULL_PTR
Reason: Iterating over None raises TypeError ('NoneType' object is not iterable)

Semantic model: None is not iterable, for-loop requires iterable.
"""

def get_items(include):
    if include:
        return ["a", "b", "c"]
    return None

def main():
    # BUG: get_items returns None when include=False
    items = get_items(False)
    # Iterating over None raises TypeError
    for item in items:
        print(item)

if __name__ == "__main__":
    main()
