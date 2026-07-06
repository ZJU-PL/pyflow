"""
ITERATOR_INVALID True Positive #1: Dict modification during iteration
Expected: BUG (RuntimeError: dictionary changed size during iteration)

Semantic bug: Modifying a dictionary while iterating over it invalidates
the iterator, violating the iterator protocol invariant.
"""

def process_items():
    data = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
    
    # BUG: Modifying dict during iteration over keys
    for key in data:
        if data[key] > 2:
            del data[key]  # RuntimeError: dictionary changed size during iteration
    
    return data

if __name__ == '__main__':
    result = process_items()
    print(f"Result: {result}")
