# ITERATOR_INVALID: dict deletion during iteration (BUG)
d = {'a': 1, 'b': 2, 'c': 3}
for key in d:
    if key == 'a':
        del d['c']  # Delete key during iteration - RuntimeError
