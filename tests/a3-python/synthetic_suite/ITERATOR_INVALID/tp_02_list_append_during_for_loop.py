"""
ITERATOR_INVALID True Positive #2: List modification during for-loop
Expected: BUG (Iterator invalidation - infinite or incorrect iteration)

Semantic bug: Modifying a list during iteration can cause:
1. Infinite loops (if appending)
2. Skipped elements (if removing)
3. Index-based iteration corruption

This creates an infinite loop as the list keeps growing.
"""

def process_list():
    items = [1, 2, 3]
    
    # BUG: Appending to list while iterating causes infinite growth
    count = 0
    for item in items:
        if count > 10:  # Safety guard to prevent actual infinite loop in test
            break
        items.append(item * 2)  # List grows unboundedly
        count += 1
    
    return items

if __name__ == '__main__':
    result = process_list()
    print(f"Result length: {len(result)}, first 10: {result[:10]}")
