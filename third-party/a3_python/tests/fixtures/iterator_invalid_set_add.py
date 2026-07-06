# ITERATOR_INVALID: set mutation during iteration (BUG)
s = {1, 2, 3, 4, 5}
for item in s:
    if item == 3:
        s.add(99)  # Mutate set during iteration - RuntimeError
