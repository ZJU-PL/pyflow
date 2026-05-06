"""
ITERATOR_INVALID True Positive #5: Dictionary keys view mutation
Expected: BUG (RuntimeError: dictionary changed size during iteration)

Semantic bug: Iterating over dict.keys() and modifying the dict
invalidates the view iterator.
"""

def process_keys():
    data = {'x': 10, 'y': 20, 'z': 30, 'w': 40}
    
    # BUG: Modifying dict while iterating over keys view
    for key in data.keys():
        if data[key] > 15:
            data[key + '_backup'] = data[key]  # RuntimeError: dict changed during iteration
    
    return data

if __name__ == '__main__':
    result = process_keys()
    print(f"Result: {result}")
