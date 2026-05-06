# Test fixture: Unbounded list growth in loop
# BUG: This exhibits unbounded heap growth

def unbounded_list_growth():
    """Append to list in infinite loop - unbounded heap growth."""
    items = []
    i = 0
    while i < 100000:  # Simulate unbounded (will be caught by bounded model checker)
        items.append(i)
        i += 1
    return items
