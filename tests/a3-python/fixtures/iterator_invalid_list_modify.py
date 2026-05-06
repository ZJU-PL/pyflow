# ITERATOR_INVALID: list modification during iteration (BUG - silent)
# This is undefined behavior in Python - may skip elements
lst = [1, 2, 3, 4, 5]
for i, val in enumerate(lst):
    if val == 3:
        lst.append(99)  # Modifies list during iteration
        # This doesn't raise, but causes incorrect iteration behavior
