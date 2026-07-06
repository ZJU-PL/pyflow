"""
ITERATOR_INVALID True Positive #3: Set modification during iteration
Expected: BUG (RuntimeError: Set changed size during iteration)

Semantic bug: Modifying a set while iterating over it invalidates
the iterator.
"""

def process_set():
    values = {1, 2, 3, 4, 5}
    
    # BUG: Adding to set during iteration
    for val in values:
        if val % 2 == 0:
            values.add(val * 10)  # RuntimeError: Set changed size during iteration
    
    return values

if __name__ == '__main__':
    result = process_set()
    print(f"Result: {result}")
