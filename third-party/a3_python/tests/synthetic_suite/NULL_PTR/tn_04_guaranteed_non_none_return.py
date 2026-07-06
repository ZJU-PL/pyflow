"""
NULL_PTR True Negative #4: Guaranteed non-None return

Ground truth: SAFE
Bug type: NULL_PTR
Reason: Function always returns non-None value

Semantic model: All control paths return non-None value.
"""

def get_items(include):
    if include:
        return ["a", "b", "c"]
    # SAFE: Always returns list (empty or populated)
    return []

def main():
    # SAFE: get_items never returns None
    items = get_items(False)
    # Iterating over guaranteed list is safe
    for item in items:
        print(item)

if __name__ == "__main__":
    main()
