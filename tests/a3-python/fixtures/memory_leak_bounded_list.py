# Test fixture: Bounded list growth
# NON-BUG: This has a fixed upper bound on heap size

def bounded_list_growth():
    """Append to list with bounded iterations - not a leak."""
    items = []
    for i in range(10):  # Fixed, small bound
        items.append(i)
    return items
